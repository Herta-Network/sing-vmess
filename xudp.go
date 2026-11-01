package vmess

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type XUDPConn struct {
	net.Conn
	writer          N.ExtendedWriter
	destination     M.Socksaddr
	requestWritten  atomic.Bool
	globalID        [8]byte
	readWaitOptions N.ReadWaitOptions
	readAccess      sync.Mutex
	writeAccess     sync.Mutex
	readErr         error
	writeErr        error
	readScratch     [256]byte
	metadataReader  io.LimitedReader
}

func NewXUDPConn(conn net.Conn, globalID [8]byte, destination M.Socksaddr) *XUDPConn {
	return &XUDPConn{
		Conn:        conn,
		writer:      bufio.NewExtendedWriter(conn),
		destination: destination,
		globalID:    globalID,
	}
}

func (c *XUDPConn) Read(p []byte) (n int, err error) {
	n, _, err = c.ReadFrom(p)
	return
}

func (c *XUDPConn) Write(p []byte) (n int, err error) {
	return c.WriteTo(p, c.destination)
}

func (c *XUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	length, destination, err := c.readPacketHeader()
	if err != nil {
		return 0, nil, err
	}
	if len(p) < length {
		return 0, nil, c.discardPayload(length)
	}
	n, err := io.ReadFull(c.Conn, p[:length])
	if err != nil {
		c.readErr = err
		return n, nil, err
	}
	if destination.IsFqdn() {
		return n, destination, nil
	}
	return n, destination.UDPAddr(), nil
}

func (c *XUDPConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	length, destination, err := c.readPacketHeader()
	if err != nil {
		return M.Socksaddr{}, err
	}
	if buffer.FreeLen() < length {
		return M.Socksaddr{}, c.discardPayload(length)
	}
	if _, err := buffer.ReadFullFrom(c.Conn, length); err != nil {
		c.readErr = err
		return M.Socksaddr{}, err
	}
	return destination, nil
}

func (c *XUDPConn) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	c.readWaitOptions = options
	return false
}

func (c *XUDPConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	length, destination, err := c.readPacketHeader()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	buffer := c.readWaitOptions.NewBufferSize(length)
	if _, err = buffer.ReadFullFrom(c.Conn, length); err != nil {
		c.readErr = err
		buffer.Release()
		return nil, M.Socksaddr{}, err
	}
	c.readWaitOptions.PostReturn(buffer)
	return buffer, destination, nil
}

// Caller holds readAccess. Header-only keepalives are consumed iteratively;
// every public read shares this parser and packet boundary handling.
func (c *XUDPConn) readPacketHeader() (size int, target M.Socksaddr, err error) {
	if c.readErr != nil {
		return 0, M.Socksaddr{}, c.readErr
	}
	retryable := false
	defer func() {
		if err != nil && !retryable {
			c.readErr = err
		}
	}()
	for {
		if n, readErr := io.ReadFull(c.Conn, c.readScratch[:6]); readErr != nil {
			var timeout net.Error
			retryable = n == 0 && errors.As(readErr, &timeout) && timeout.Timeout()
			return 0, M.Socksaddr{}, readErr
		}
		length := binary.BigEndian.Uint16(c.readScratch[:2])
		status, option := c.readScratch[4], c.readScratch[5]
		if length < 4 {
			return 0, M.Socksaddr{}, E.New("bad XUDP header length: ", length)
		}
		destination := c.destination
		c.metadataReader = io.LimitedReader{R: c.Conn, N: int64(length - 4)}
		switch status {
		case StatusNew:
			return 0, M.Socksaddr{}, E.New("unexpected frame new")
		case StatusKeep:
			if length > 4 {
				if _, err := io.ReadFull(&c.metadataReader, c.readScratch[:1]); err != nil {
					return 0, M.Socksaddr{}, err
				}
				if c.readScratch[0] != NetworkUDP {
					return 0, M.Socksaddr{}, E.New("unexpected XUDP network")
				}
				var err error
				destination, err = AddressSerializer.ReadAddrPortWithScratch(&c.metadataReader, c.readScratch[:])
				if err != nil {
					return 0, M.Socksaddr{}, err
				}
				if !destination.IsValid() || len(destination.Fqdn) > 255 {
					return 0, M.Socksaddr{}, E.New("invalid XUDP destination")
				}
				destination = destination.Unwrap()
			}
		case StatusEnd:
			if option&OptionError != 0 {
				return 0, M.Socksaddr{}, net.ErrClosed
			}
			return 0, M.Socksaddr{}, io.EOF
		case StatusKeepAlive:
		default:
			return 0, M.Socksaddr{}, E.New("unexpected XUDP frame: ", status)
		}
		if c.metadataReader.N > 0 {
			if _, err := io.Copy(io.Discard, &c.metadataReader); err != nil {
				return 0, M.Socksaddr{}, err
			}
			if c.metadataReader.N != 0 {
				return 0, M.Socksaddr{}, io.ErrUnexpectedEOF
			}
		}
		if option&OptionError != 0 {
			return 0, M.Socksaddr{}, net.ErrClosed
		}
		if option&OptionData == 0 {
			continue
		}
		if _, err := io.ReadFull(c.Conn, c.readScratch[:2]); err != nil {
			return 0, M.Socksaddr{}, err
		}
		return int(binary.BigEndian.Uint16(c.readScratch[:2])), destination, nil
	}
}

func (c *XUDPConn) discardPayload(length int) error {
	c.metadataReader = io.LimitedReader{R: c.Conn, N: int64(length)}
	if _, err := io.Copy(io.Discard, &c.metadataReader); err != nil {
		c.readErr = err
		return err
	}
	if c.metadataReader.N != 0 {
		c.readErr = io.ErrUnexpectedEOF
		return c.readErr
	}
	return io.ErrShortBuffer
}

func (c *XUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return bufio.WritePacketBuffer(c, buf.As(p), M.SocksaddrFromNet(addr))
}

func (c *XUDPConn) frontHeadroom(addrLen int) int {
	if !c.requestWritten.Load() {
		var headerLen int
		headerLen += 2 // frame len
		headerLen += 5 // frame header
		headerLen += addrLen
		if c.globalID != [8]byte{} {
			headerLen += 8 // global ID
		}
		headerLen += 2 // payload len
		return headerLen
	} else {
		return 7 + addrLen + 2
	}
}

func (c *XUDPConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if c.writeErr != nil {
		buffer.Release()
		return c.writeErr
	}
	dataLen := buffer.Len()
	if dataLen > 65535 || (!destination.IsValid() || len(destination.Fqdn) > 255) {
		buffer.Release()
		return E.New("invalid XUDP packet")
	}
	buffer = N.NewReadWaitOptions(nil, c).Copy(buffer)
	addrLen := M.SocksaddrSerializer.AddrPortLen(destination)
	if !c.requestWritten.Load() {
		headerLen := c.frontHeadroom(addrLen)
		header := buf.With(buffer.ExtendHeader(headerLen))
		binary.BigEndian.PutUint16(header.Extend(2), uint16(headerLen-4))
		common.Must(
			header.WriteByte(0),
			header.WriteByte(0),
			header.WriteByte(1), // frame type new
			header.WriteByte(1), // option data
			header.WriteByte(NetworkUDP),
		)
		err := AddressSerializer.WriteAddrPortBuffer(header, destination)
		if err != nil {
			buffer.Release()
			return err
		}
		if c.globalID != [8]byte{} {
			common.Must1(header.Write(c.globalID[:]))
		}
		binary.BigEndian.PutUint16(header.Extend(2), uint16(dataLen))
		c.requestWritten.Store(true)
	} else {
		header := buffer.ExtendHeader(c.frontHeadroom(addrLen))
		binary.BigEndian.PutUint16(header, uint16(5+addrLen))
		header[2] = 0
		header[3] = 0
		header[4] = 2 // frame keep
		header[5] = 1 // option data
		header[6] = NetworkUDP
		err := AddressSerializer.WriteAddrPortBuffer(buf.With(header[7:]), destination)
		if err != nil {
			buffer.Release()
			return err
		}
		binary.BigEndian.PutUint16(header[7+addrLen:], uint16(dataLen))
	}
	err := c.writer.WriteBuffer(buffer)
	if err != nil {
		c.writeErr = err
		_ = c.Conn.Close()
	}
	return err
}

func (c *XUDPConn) FrontHeadroom() int {
	return 9 + M.MaxSocksaddrLength + 8
}

func (c *XUDPConn) NeedHandshake() bool {
	return !c.requestWritten.Load()
}

func (c *XUDPConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *XUDPConn) Upstream() any {
	return c.Conn
}
