package vmess

import (
	std_bufio "bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func HandleMuxConnection(ctx context.Context, conn net.Conn, metadata M.Metadata, handler Handler) error {
	ctx, cancel := context.WithCancelCause(ctx)
	session := &serverSession{
		ctx:          ctx,
		metadata:     metadata,
		conn:         conn,
		directWriter: bufio.NewExtendedWriter(conn),
		handler:      handler,
		streams:      make(map[uint16]*serverStream),
		writer:       std_bufio.NewWriter(conn),
	}
	cleaned := make(chan struct{})
	go func() {
		defer close(cleaned)
		<-ctx.Done()
		_ = conn.Close()
		session.cleanup(context.Cause(ctx))
	}()
	err := session.recvLoop()
	// The former byte pipe could not read the next frame until its preceding
	// packet was handed off. Preserve that EOF boundary with queued packets:
	// notify readers, drain accepted packets, then cancel handler contexts.
	// Parent cancellation independently aborts queues and wakes this wait.
	cause := err
	if ctx.Err() != nil {
		cause = context.Cause(ctx)
	}
	session.cleanup(cause)
	session.packetBudget.waitDrained()
	cancel(err)
	<-cleaned
	return err
}

type serverSession struct {
	ctx            context.Context
	metadata       M.Metadata
	conn           net.Conn
	directWriter   N.ExtendedWriter
	handler        Handler
	streamAccess   sync.RWMutex
	streams        map[uint16]*serverStream
	writer         *std_bufio.Writer
	writeAccess    sync.Mutex
	writeErr       error
	writeScratch   [9 + M.MaxSocksaddrLength]byte
	readScratch    [256]byte
	metadataReader io.LimitedReader
	packetBudget   muxPacketBudget
	closed         bool // protected by streamAccess
}

type serverStream struct {
	network     byte
	destination M.Socksaddr
	pipe        *io.PipeWriter
	packets     *muxPacketQueue
}

func (c *serverSession) recvLoop() error {
	for {
		err := c.recv()
		if err != nil {
			return E.Cause(err, "mux connection closed")
		}
	}
}

func (c *serverSession) cleanup(err error) {
	c.streamAccess.Lock()
	defer c.streamAccess.Unlock()
	c.closed = true
	discard := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	for id, stream := range c.streams {
		if stream.pipe != nil {
			_ = stream.pipe.CloseWithError(err)
		}
		delete(c.streams, id)
	}
	c.packetBudget.close(err, discard)
}

func (c *serverSession) recv() error {
	if _, err := io.ReadFull(c.conn, c.readScratch[:6]); err != nil {
		return E.Cause(err, "read frame header")
	}
	length := binary.BigEndian.Uint16(c.readScratch[:2])
	if length < 4 {
		return E.New("bad mux header length: ", length)
	}
	sessionID := binary.BigEndian.Uint16(c.readScratch[2:4])
	status, option := c.readScratch[4], c.readScratch[5]
	var network byte
	var destination M.Socksaddr
	var err error
	if length > 4 {
		c.metadataReader = io.LimitedReader{R: c.conn, N: int64(length - 4)}
		if _, err = io.ReadFull(&c.metadataReader, c.readScratch[:1]); err != nil {
			return err
		}
		network = c.readScratch[0]
		destination, err = AddressSerializer.ReadAddrPortWithScratch(&c.metadataReader, c.readScratch[:])
		if err != nil {
			return err
		}
		if !destination.IsValid() || len(destination.Fqdn) > 255 {
			return E.New("invalid mux destination")
		}
		if c.metadataReader.N > 0 {
			if _, err = io.Copy(io.Discard, &c.metadataReader); err != nil {
				return err
			}
			if c.metadataReader.N != 0 {
				return io.ErrUnexpectedEOF
			}
		}
	}

	var stream *serverStream
	switch status {
	case StatusNew:
		if network != NetworkTCP && network != NetworkUDP {
			return E.New("bad network: ", network)
		}
		stream = &serverStream{network: network, destination: destination}
		var pipeIn *io.PipeReader
		if network == NetworkTCP {
			pipeIn, stream.pipe = io.Pipe()
		} else {
			stream.packets = newMuxPacketQueue(&c.packetBudget)
		}
		c.streamAccess.Lock()
		_, duplicate := c.streams[sessionID]
		if c.closed || duplicate {
			c.streamAccess.Unlock()
			stream.close(io.ErrClosedPipe, true)
			if pipeIn != nil {
				_ = pipeIn.Close()
			}
			return E.New("closed or duplicate mux stream: ", sessionID)
		}
		c.streams[sessionID] = stream
		c.streamAccess.Unlock()
		go func(stream *serverStream, destination M.Socksaddr) {
			metadata := M.Metadata{Source: c.metadata.Source, Destination: destination}
			var hErr error
			if network == NetworkTCP {
				hErr = c.handler.NewConnection(c.ctx, &serverMuxConn{sessionID: sessionID, pipe: pipeIn, session: c, stream: stream}, metadata)
			} else {
				hErr = c.handler.NewPacketConnection(c.ctx, &serverMuxPacketConn{sessionID: sessionID, packets: stream.packets, session: c, stream: stream, destination: destination}, metadata)
			}
			if hErr != nil {
				c.handler.NewError(c.ctx, hErr)
				_ = c.closeStream(sessionID, stream, hErr)
			}
		}(stream, destination)
	case StatusKeep:
		var loaded bool
		c.streamAccess.Lock()
		stream, loaded = c.streams[sessionID]
		c.streamAccess.Unlock()
		if !loaded {
			go c.syncClose(sessionID, true)
		}
	case StatusEnd:
		if option&OptionError == OptionError {
			err = E.New("remote closed wth error")
		}
		c.localClose(sessionID, nil, err, false)
	case StatusKeepAlive:
	default:
		return E.New("bad session status: ", status)
	}

	if option&OptionData != OptionData {
		return nil
	}

	_, err = io.ReadFull(c.conn, c.readScratch[:2])
	if err != nil {
		return err
	}

	length = binary.BigEndian.Uint16(c.readScratch[:2])
	if length == 0 && (stream == nil || stream.network != NetworkUDP) {
		return nil
	}

	if stream == nil {
		return common.Error(io.CopyN(io.Discard, c.conn, int64(length)))
	}

	if !destination.IsValid() || len(destination.Fqdn) > 255 {
		destination = stream.destination
	}
	if stream.network == NetworkUDP {
		options := stream.packets.readOptions()
		data := options.NewBufferSize(int(length))
		if _, err = data.ReadFullFrom(c.conn, int(length)); err != nil {
			data.Release()
			return err
		}
		options.PostReturn(data)
		if err = stream.packets.push(muxPacket{data, destination}); err != nil {
			return c.closeStream(sessionID, stream, err)
		}
		return nil
	}
	data := buf.NewSize(int(length))
	defer data.Release()
	if _, err = data.ReadFullFrom(c.conn, int(length)); err != nil {
		return err
	}
	if _, err = stream.pipe.Write(data.Bytes()); err != nil {
		return c.closeStream(sessionID, stream, err)
	}
	return nil
}

func (s *serverStream) close(err error, discard bool) {
	if s.pipe != nil {
		_ = s.pipe.CloseWithError(err)
	}
	if s.packets != nil {
		s.packets.close(err, discard)
	}
}

func (c *serverSession) syncWrite(sessionID uint16, data []byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if err := c.writeStateError(); err != nil {
		return 0, c.failWrite(err)
	}
	err := c.writeFrame(sessionID, data)
	if err != nil {
		return 0, c.failWrite(err)
	}
	if err = c.writer.Flush(); err != nil {
		return 0, c.failWrite(err)
	}
	return len(data), nil
}

func (c *serverSession) writeFrame(sessionID uint16, data []byte) error {
	for {
		size := len(data)
		if size > 65535 {
			size = 65535
		}
		header := c.writeScratch[:8]
		binary.BigEndian.PutUint16(header, 4)
		binary.BigEndian.PutUint16(header[2:], sessionID)
		header[4], header[5] = StatusKeep, OptionData
		binary.BigEndian.PutUint16(header[6:], uint16(size))
		if _, err := c.writer.Write(header); err != nil {
			return err
		}
		if _, err := c.writer.Write(data[:size]); err != nil {
			return err
		}
		data = data[size:]
		if len(data) == 0 {
			return nil
		}
	}
}

func (c *serverSession) syncWritePacket(sessionID uint16, data []byte, destination M.Socksaddr) (int, error) {
	if len(data) > 65535 || (!destination.IsValid() || len(destination.Fqdn) > 255) {
		return 0, os.ErrInvalid
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if err := c.writeStateError(); err != nil {
		return 0, c.failWrite(err)
	}
	err := c.writePacketFrame(sessionID, data, destination)
	if err != nil {
		return 0, c.failWrite(err)
	}
	if err = c.writer.Flush(); err != nil {
		return 0, c.failWrite(err)
	}
	return len(data), nil
}

func (c *serverSession) writePacketFrame(sessionID uint16, data []byte, destination M.Socksaddr) error {
	headerLen := 9 + AddressSerializer.AddrPortLen(destination)
	header := c.writeScratch[:headerLen]
	if err := encodeMuxPacketHeader(header, sessionID, len(data), destination); err != nil {
		return err
	}
	if _, err := c.writer.Write(header); err != nil {
		return err
	}
	return common.Error(c.writer.Write(data))
}

func (c *serverSession) closeStream(sessionID uint16, stream *serverStream, err error) error {
	// Closing a retired stream must still release its queue, but must not close
	// a later stream that reuses the same wire ID.
	stream.close(err, true)
	if c.localClose(sessionID, stream, err, true) {
		return c.syncClose(sessionID, err != nil)
	}
	return nil
}

func (c *serverSession) localClose(sessionID uint16, expected *serverStream, err error, discard bool) bool {
	c.streamAccess.Lock()
	stream, loaded := c.streams[sessionID]
	if loaded && (expected == nil || expected == stream) {
		delete(c.streams, sessionID)
	} else {
		loaded = false
	}
	c.streamAccess.Unlock()
	if loaded {
		stream.close(err, discard)
	}
	return loaded
}

func (c *serverSession) syncClose(sessionID uint16, hasError bool) error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if err := c.writeStateError(); err != nil {
		return c.failWrite(err)
	}
	err := c.writeCloseFrame(sessionID, hasError)
	if err != nil {
		return c.failWrite(err)
	}
	if err = c.writer.Flush(); err != nil {
		return c.failWrite(err)
	}
	return nil
}

func (c *serverSession) writeCloseFrame(sessionID uint16, hasError bool) error {
	header := c.writeScratch[:6]
	binary.BigEndian.PutUint16(header, 4)
	binary.BigEndian.PutUint16(header[2:], sessionID)
	header[4], header[5] = StatusEnd, 0
	if hasError {
		header[5] = OptionError
	}
	return common.Error(c.writer.Write(header))
}

func encodeMuxPacketHeader(header []byte, sessionID uint16, size int, destination M.Socksaddr) error {
	binary.BigEndian.PutUint16(header, uint16(len(header)-4))
	binary.BigEndian.PutUint16(header[2:], sessionID)
	header[4], header[5], header[6] = StatusKeep, OptionData, NetworkUDP
	if err := AddressSerializer.WriteAddrPortBuffer(buf.With(header[7:len(header)-2]), destination); err != nil {
		return err
	}
	binary.BigEndian.PutUint16(header[len(header)-2:], uint16(size))
	return nil
}

// All stream, packet and control writes share the cipher/transport writer.
// Flush older borrowed writes before handing off an owned frame.
func (c *serverSession) writeOwned(buffer *buf.Buffer) error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if err := c.writeStateError(); err != nil {
		buffer.Release()
		return err
	}
	if c.writer != nil && c.writer.Buffered() != 0 {
		if err := c.writer.Flush(); err != nil {
			buffer.Release()
			return c.failWrite(err)
		}
	}
	return c.failWrite(c.directWriter.WriteBuffer(buffer))
}

func (c *serverSession) writeStateError() error {
	if c.writeErr != nil {
		return c.writeErr
	}
	if c.ctx != nil {
		return c.ctx.Err()
	}
	return nil
}

func (c *serverSession) failWrite(err error) error {
	if err != nil {
		c.writeErr = err
		if c.conn != nil {
			_ = c.conn.Close()
		}
	}
	return err
}

type serverMuxConn struct {
	sessionID uint16
	pipe      *io.PipeReader
	session   *serverSession
	stream    *serverStream
}

func (c *serverMuxConn) Read(b []byte) (n int, err error) {
	return c.pipe.Read(b)
}

func (c *serverMuxConn) Write(b []byte) (n int, err error) {
	return c.session.syncWrite(c.sessionID, b)
}

func (c *serverMuxConn) WriteBuffer(buffer *buf.Buffer) error {
	dataLen := buffer.Len()
	if dataLen > 65535 {
		defer buffer.Release()
		_, err := c.session.syncWrite(c.sessionID, buffer.Bytes())
		return err
	}
	buffer = N.NewReadWaitOptions(nil, c).Copy(buffer)
	header := buffer.ExtendHeader(8)
	binary.BigEndian.PutUint16(header, 4)
	binary.BigEndian.PutUint16(header[2:], c.sessionID)
	header[4], header[5] = StatusKeep, OptionData
	binary.BigEndian.PutUint16(header[6:], uint16(dataLen))
	return c.session.writeOwned(buffer)
}

func (c *serverMuxConn) FrontHeadroom() int {
	return 8
}

func (c *serverMuxConn) UpstreamWriter() any {
	return c.session.directWriter
}

func (c *serverMuxConn) Close() error {
	_ = c.pipe.Close()
	return c.session.closeStream(c.sessionID, c.stream, nil)
}

func (c *serverMuxConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverMuxConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverMuxConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxConn) NeedAdditionalReadDeadline() bool {
	return true
}

var (
	_ PacketConn         = (*serverMuxPacketConn)(nil)
	_ N.PacketReadWaiter = (*serverMuxPacketConn)(nil)
)

type serverMuxPacketConn struct {
	sessionID   uint16
	packets     *muxPacketQueue
	stream      *serverStream
	readAccess  sync.Mutex
	session     *serverSession
	destination M.Socksaddr
}

func (c *serverMuxPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *serverMuxPacketConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.destination)
}

func (c *serverMuxPacketConn) RemoteAddr() net.Addr {
	return c.destination.UDPAddr()
}

func (c *serverMuxPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	packet, err := c.packets.pop()
	if err != nil {
		return 0, nil, err
	}
	defer packet.buffer.Release()
	if len(p) < packet.buffer.Len() {
		return 0, nil, io.ErrShortBuffer
	}
	return copy(p, packet.buffer.Bytes()), packet.destination, nil
}

func (c *serverMuxPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	packet, err := c.packets.pop()
	if err != nil {
		return M.Socksaddr{}, err
	}
	defer packet.buffer.Release()
	if buffer.FreeLen() < packet.buffer.Len() {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	_, err = buffer.Write(packet.buffer.Bytes())
	return packet.destination, err
}

func (c *serverMuxPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	c.packets.setOptions(options)
	return false
}

func (c *serverMuxPacketConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	packet, err := c.packets.pop()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	return c.packets.readOptions().Copy(packet.buffer), packet.destination, nil
}

func (c *serverMuxPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.session.syncWritePacket(c.sessionID, p, M.SocksaddrFromNet(addr))
}

func (c *serverMuxPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	dataLen := buffer.Len()
	if dataLen > 65535 || (!destination.IsValid() || len(destination.Fqdn) > 255) {
		buffer.Release()
		return os.ErrInvalid
	}
	buffer = N.NewReadWaitOptions(nil, c).Copy(buffer)
	header := buffer.ExtendHeader(9 + AddressSerializer.AddrPortLen(destination))
	if err := encodeMuxPacketHeader(header, c.sessionID, dataLen, destination); err != nil {
		buffer.Release()
		return err
	}
	return c.session.writeOwned(buffer)
}

func (c *serverMuxPacketConn) FrontHeadroom() int {
	return 9 + M.MaxSocksaddrLength
}

func (c *serverMuxPacketConn) UpstreamWriter() any {
	return c.session.directWriter
}

func (c *serverMuxPacketConn) Close() error {
	return c.session.closeStream(c.sessionID, c.stream, nil)
}

func (c *serverMuxPacketConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverMuxPacketConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxPacketConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxPacketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}
