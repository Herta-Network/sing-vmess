package vmess

import (
	std_bufio "bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func muxTestFrame(status byte, id uint16, payload []byte, target M.Socksaddr) []byte {
	var wire bytes.Buffer
	binary.Write(&wire, binary.BigEndian, uint16(5+AddressSerializer.AddrPortLen(target)))
	binary.Write(&wire, binary.BigEndian, id)
	wire.WriteByte(status)
	wire.WriteByte(OptionData)
	wire.WriteByte(NetworkUDP)
	AddressSerializer.WriteAddrPort(&wire, target)
	binary.Write(&wire, binary.BigEndian, uint16(len(payload)))
	wire.Write(payload)
	return wire.Bytes()
}

func awaitMuxTest(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("mux operation blocked")
		return nil
	}
}

func TestMuxOwnedReceiveHeadroomAndBoundaries(t *testing.T) {
	target := M.ParseSocksaddr("[2001:db8::1]:5353")
	queue := newMuxPacketQueue(new(muxPacketBudget))
	defer queue.close(nil, true)
	conn := &serverMuxPacketConn{packets: queue}
	conn.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 64, RearHeadroom: 32})
	for _, size := range []int{0, 1, 1200, 60000, 65535} {
		payload := bytes.Repeat([]byte{0x57}, size)
		session := &serverSession{conn: &frameReaderConn{Reader: bytes.NewReader(muxTestFrame(StatusKeep, 1, payload, target))}, streams: map[uint16]*serverStream{1: {network: NetworkUDP, destination: target, packets: queue}}}
		if err := session.recv(); err != nil {
			t.Fatal(err)
		}
		queue.budget.Lock()
		original := queue.items[queue.head].buffer
		queue.budget.Unlock()
		got, address, err := conn.WaitReadPacket()
		if err != nil {
			t.Fatal(err)
		}
		if got != original || address != target || got.Start() != 64 || got.FreeLen() < 32 || !bytes.Equal(got.Bytes(), payload) {
			t.Fatal("packet copied, truncated or lost headroom/address")
		}
		got.Release()
	}
	queued := make(chan error, 1)
	go func() {
		for _, payload := range []string{"too long", "next", "owned"} {
			b := buf.NewSize(len(payload))
			b.WriteString(payload)
			if err := queue.push(muxPacket{b, target}); err != nil {
				queued <- err
				return
			}
		}
		queued <- nil
	}()

	if _, _, err := conn.ReadFrom(make([]byte, 1)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal(err)
	}
	buffer := buf.NewSize(4)
	defer buffer.Release()
	if address, err := conn.ReadPacket(buffer); err != nil || address != target || string(buffer.Bytes()) != "next" {
		t.Fatalf("read after short buffer: %v", err)
	}
	got, _, err := conn.WaitReadPacket()
	if err != nil || string(got.Bytes()) != "owned" {
		t.Fatalf("mixed reader order: %v", err)
	}
	got.Release()
	if err := awaitMuxTest(t, queued); err != nil {
		t.Fatal(err)
	}
}

func TestMuxQueueLimitsCloseAndEOF(t *testing.T) {
	for _, sessionLimit := range []bool{false, true} {
		budget := new(muxPacketBudget)
		queue := newMuxPacketQueue(budget)
		limit := muxPacketQueueSize
		if sessionLimit {
			limit = muxSessionQueuedPackets
		}
		var buffers []*buf.Buffer
		for i := 0; i < limit; i++ {
			if sessionLimit && i%muxPacketQueueSize == 0 {
				queue = newMuxPacketQueue(budget)
			}
			buffer := buf.NewSize(1)
			buffer.WriteByte(byte(i))
			buffers = append(buffers, buffer)
			if err := queue.push(muxPacket{buffer: buffer}); err != nil {
				t.Fatal(err)
			}
		}
		if sessionLimit {
			queue = newMuxPacketQueue(budget)
		}
		blocked := buf.NewSize(1)
		blocked.WriteByte(99)
		done := make(chan error, 1)
		go func() { done <- queue.push(muxPacket{buffer: blocked}) }()
		select {
		case err := <-done:
			t.Fatalf("queue failed to apply backpressure: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
		budget.close(context.Canceled, true)
		if err := awaitMuxTest(t, done); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		for _, buffer := range append(buffers, blocked) {
			if buffer.RawCap() != 0 {
				t.Fatal("closed queue retained payload")
			}
		}
		if budget.queued != 0 || len(budget.queues) != 0 {
			t.Fatal("session retained queues")
		}
		if _, err := queue.pop(); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	budget := new(muxPacketBudget)
	queue := newMuxPacketQueue(budget)
	packet := buf.NewSize(1)
	packet.WriteByte(7)
	queue.push(muxPacket{buffer: packet})
	queue.close(nil, false)
	got, err := queue.pop()
	if err != nil || got.buffer != packet {
		t.Fatal("EOF discarded a received packet")
	}
	got.buffer.Release()
	if _, err := queue.pop(); err != io.EOF {
		t.Fatal(err)
	}
	if budget.queued != 0 || len(budget.queues) != 0 {
		t.Fatal("drained EOF retained queue")
	}
}

func TestMuxRetiredStreamCloseKeepsReusedID(t *testing.T) {
	session := &serverSession{streams: make(map[uint16]*serverStream)}
	old := &serverStream{network: NetworkUDP, packets: newMuxPacketQueue(&session.packetBudget)}
	session.streams[1] = old
	buffer := buf.NewSize(1)
	buffer.WriteByte(1)
	old.packets.push(muxPacket{buffer: buffer})
	session.localClose(1, nil, nil, false)
	next := &serverStream{network: NetworkUDP, packets: newMuxPacketQueue(&session.packetBudget)}
	session.streams[1] = next
	if err := (&serverMuxPacketConn{sessionID: 1, session: session, stream: old, packets: old.packets}).Close(); err != nil {
		t.Fatal(err)
	}
	if session.streams[1] != next || next.packets.closed || buffer.RawCap() != 0 {
		t.Fatal("retired close affected a replacement stream")
	}
	session.cleanup(context.Canceled)
}

type muxTestHandler struct {
	packets chan N.PacketConn
	context chan context.Context
}

func (h *muxTestHandler) NewConnection(context.Context, net.Conn, M.Metadata) error { return nil }
func (h *muxTestHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, _ M.Metadata) error {
	if h.context != nil {
		h.context <- ctx
	}
	h.packets <- conn
	return nil
}

type muxEOFConn struct {
	frameReaderConn
	eof  chan struct{}
	once sync.Once
}

func (c *muxEOFConn) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		c.once.Do(func() { close(c.eof) })
	}
	return n, err
}

func (*muxEOFConn) Close() error                { return nil }
func (*muxEOFConn) Write(p []byte) (int, error) { return len(p), nil }

func TestMuxEOFWaitsForAcceptedPacketsBeforeCancel(t *testing.T) {
	target := M.ParseSocksaddr("1.2.3.4:53")
	raw := &muxEOFConn{frameReaderConn: frameReaderConn{Reader: bytes.NewReader(muxTestFrame(StatusNew, 0, []byte("last"), target))}, eof: make(chan struct{})}
	handler := &muxTestHandler{packets: make(chan N.PacketConn, 1), context: make(chan context.Context, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- HandleMuxConnection(ctx, raw, M.Metadata{}, handler) }()
	var conn N.PacketConn
	select {
	case conn = <-handler.packets:
	case <-time.After(5 * time.Second):
		t.Fatal("stream not opened")
	}
	child := <-handler.context
	select {
	case <-raw.eof:
	case <-time.After(time.Second):
		t.Fatal("receiver never reached EOF")
	}
	select {
	case <-child.Done():
		t.Fatal("EOF canceled a context before handing off its packet")
	case <-time.After(20 * time.Millisecond):
	}
	buffer, addr, err := conn.(N.PacketReadWaiter).WaitReadPacket()
	if err != nil || addr != target || string(buffer.Bytes()) != "last" {
		t.Fatalf("final packet: %v", err)
	}
	buffer.Release()
	if err = awaitMuxTest(t, done); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
}
func (*muxTestHandler) NewError(context.Context, error) {}

func TestMuxCancelInterruptsFullQueueAndNetworkRead(t *testing.T) {
	for _, fill := range []bool{false, true} {
		left, right := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		handler := &muxTestHandler{packets: make(chan N.PacketConn, 1)}
		done := make(chan error, 1)
		go func() { done <- HandleMuxConnection(ctx, right, M.Metadata{}, handler) }()
		written := make(chan error, 1)
		target := M.ParseSocksaddr("1.2.3.4:53")
		go func() {
			_, err := left.Write(muxTestFrame(StatusNew, 0, []byte{1}, target))
			if fill {
				for i := 0; i < 8 && err == nil; i++ {
					_, err = left.Write(muxTestFrame(StatusKeep, 0, []byte{1}, target))
				}
			}
			written <- err
		}()
		var conn *serverMuxPacketConn
		select {
		case p := <-handler.packets:
			conn = p.(*serverMuxPacketConn)
		case <-time.After(5 * time.Second):
			cancel()
			left.Close()
			t.Fatal("stream not opened")
		}
		if fill {
			deadline := time.Now().Add(5 * time.Second)
			for {
				conn.packets.budget.Lock()
				size := conn.packets.size
				conn.packets.budget.Unlock()
				if size == muxPacketQueueSize {
					break
				}
				if time.Now().After(deadline) {
					cancel()
					left.Close()
					t.Fatal("queue did not fill")
				}
				time.Sleep(time.Millisecond)
			}
		}
		cancel()
		if err := awaitMuxTest(t, done); err == nil {
			t.Fatal("canceled session succeeded")
		}
		left.Close()
		awaitMuxTest(t, written)
		if _, _, err := conn.WaitReadPacket(); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if conn.packets.budget.queued != 0 {
			t.Fatal("cancel retained queued payloads")
		}
	}
}

type muxWireSink struct{ bytes.Buffer }

func (s *muxWireSink) Write(p []byte) (int, error) { return s.Buffer.Write(p) }

func TestMuxConcurrentOwnedAndBorrowedCipherWrites(t *testing.T) {
	var wire muxWireSink
	key, nonce := make([]byte, 16), make([]byte, 16)
	option := byte(RequestOptionChunkStream | RequestOptionChunkMasking)
	writer := bufio.NewExtendedWriter(CreateWriter(&wire, nil, key, nonce, key, nonce, SecurityTypeAes128Gcm, option))
	session := &serverSession{writer: std_bufio.NewWriter(writer), directWriter: writer}
	target := M.ParseSocksaddr("1.2.3.4:53")
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			conn := &serverMuxPacketConn{sessionID: uint16(worker), session: session}
			for i := 0; i < 50; i++ {
				payload := []byte{byte(worker), byte(i)}
				var err error
				if worker%2 == 0 {
					buffer := N.NewReadWaitOptions(nil, conn).Copy(buf.As(payload))
					err = conn.WritePacket(buffer, target)
				} else {
					_, err = conn.WriteTo(payload, target)
				}
				if err != nil {
					t.Error(err)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	reader := bufio.NewChunkReader(CreateReader(bytes.NewReader(wire.Bytes()), nil, key, nonce, key, nonce, SecurityTypeAes128Gcm, option), ReadChunkSize)
	seen := make(map[[2]byte]bool)
	for i := 0; i < 400; i++ {
		var header [6]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			t.Fatal(err)
		}
		length := binary.BigEndian.Uint16(header[:])
		id := binary.BigEndian.Uint16(header[2:])
		if header[4] != StatusKeep || header[5] != OptionData || int(length) != 5+AddressSerializer.AddrPortLen(target) {
			t.Fatal("interleaved header")
		}
		var network [1]byte
		io.ReadFull(reader, network[:])
		if network[0] != NetworkUDP {
			t.Fatal("wrong network")
		}
		address, err := AddressSerializer.ReadAddrPort(reader)
		if err != nil || address != target {
			t.Fatalf("address %v: %v", address, err)
		}
		var size uint16
		if err = binary.Read(reader, binary.BigEndian, &size); err != nil || size != 2 {
			t.Fatal("wrong size")
		}
		var payload [2]byte
		if _, err = io.ReadFull(reader, payload[:]); err != nil {
			t.Fatal(err)
		}
		if uint16(payload[0]) != id || seen[payload] {
			t.Fatal("packet duplicated or reordered across streams")
		}
		seen[payload] = true
	}
	var tail [1]byte
	if n, err := reader.Read(tail[:]); n != 0 || err != io.EOF {
		t.Fatalf("trailing cipher data: %d %v", n, err)
	}
}
