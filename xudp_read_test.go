package vmess

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func TestXUDPReadAPIsSharePacketBoundaries(t *testing.T) {
	target := M.ParseSocksaddr("[2001:db8::1]:53")
	var wire bytes.Buffer
	// Keepalives must be iterative and consume their complete metadata.
	for i := 0; i < 10000; i++ {
		wire.Write([]byte{0, 5, 0, 0, StatusKeepAlive, 0, 0})
	}
	payloads := [][]byte{nil, bytes.Repeat([]byte{7}, 60000), bytes.Repeat([]byte{8}, 65535), []byte("too large"), []byte("tail")}
	for _, p := range payloads {
		wire.Write(muxTestFrame(StatusKeep, 0, p, target))
	}
	conn := NewXUDPConn(&frameReaderConn{Reader: bytes.NewReader(wire.Bytes())}, [8]byte{}, target)
	conn.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 13, RearHeadroom: 17, MaxBufferSize: 32})
	n, addr, err := conn.ReadFrom(nil)
	if err != nil || n != 0 || addr.String() != target.String() {
		t.Fatalf("empty frame: %d %v", n, err)
	}
	provided := buf.NewSize(60000)
	defer provided.Release()
	if addr, err := conn.ReadPacket(provided); err != nil || addr != target || !bytes.Equal(provided.Bytes(), payloads[1]) {
		t.Fatal("large scalar frame changed", err)
	}
	owned, addrValue, err := conn.WaitReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if addrValue != target || owned.Start() != 13 || owned.FreeLen() < 17 || !bytes.Equal(owned.Bytes(), payloads[2]) {
		t.Fatal("owned frame truncated or lost headroom")
	}
	owned.Release()
	if _, _, err = conn.ReadFrom(make([]byte, 1)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal(err)
	}
	owned, _, err = conn.WaitReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(owned.Bytes()) != "tail" {
		t.Fatal("short read lost next boundary")
	}
	owned.Release()
	if b, _, err := conn.WaitReadPacket(); b != nil || err != io.EOF {
		t.Fatalf("EOF: %v %v", b, err)
	}
}

func TestXUDPTruncatedFramesReleaseOwnedRead(t *testing.T) {
	target := M.ParseSocksaddr("example.com:53")
	valid := muxTestFrame(StatusKeep, 0, []byte("payload"), target)
	for _, wire := range [][]byte{{0, 3, 0, 0, StatusKeep, OptionData}, valid[:7], valid[:len(valid)-1]} {
		conn := NewXUDPConn(&frameReaderConn{Reader: bytes.NewReader(wire)}, [8]byte{}, target)
		conn.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 32, RearHeadroom: 64})
		buffer, _, err := conn.WaitReadPacket()
		if err == nil || buffer != nil {
			t.Fatal("truncated frame returned an owned buffer")
		}
		if again, _, nextErr := conn.WaitReadPacket(); again != nil || !errors.Is(nextErr, err) {
			t.Fatal("continued after truncated frame")
		}
	}
	end := []byte{0, 4, 0, 0, StatusEnd, 0}
	conn := NewXUDPConn(&frameReaderConn{Reader: bytes.NewReader(append(end, valid...))}, [8]byte{}, target)
	for i := 0; i < 2; i++ {
		if _, _, err := conn.WaitReadPacket(); err != io.EOF {
			t.Fatal("read after remote end", err)
		}
	}
}

type xudpWriteSink struct {
	net.Conn
	bytes.Buffer
}

func (s *xudpWriteSink) Write(p []byte) (int, error) { return s.Buffer.Write(p) }
func (s *xudpWriteSink) Read(p []byte) (int, error)  { return s.Buffer.Read(p) }

func TestXUDPConcurrentWritersHaveOneNewFrame(t *testing.T) {
	sink := &xudpWriteSink{}
	target := M.ParseSocksaddr("1.2.3.4:53")
	conn := NewXUDPConn(sink, [8]byte{}, target)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				conn.NeedHandshake()
				conn.FrontHeadroom()
				if _, err := conn.WriteTo([]byte{byte(worker), byte(i)}, target); err != nil {
					t.Error(err)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	reader := bytes.NewReader(sink.Bytes())
	seen := make(map[[2]byte]bool)
	for i := 0; i < 200; i++ {
		var header [6]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			t.Fatal(err)
		}
		want := byte(StatusKeep)
		if i == 0 {
			want = StatusNew
		}
		if header[4] != want || header[5] != OptionData {
			t.Fatal("duplicate or interleaved handshake")
		}
		length := int(binary.BigEndian.Uint16(header[:]))
		metadata := make([]byte, length-4)
		if _, err := io.ReadFull(reader, metadata); err != nil {
			t.Fatal(err)
		}
		var size uint16
		if err := binary.Read(reader, binary.BigEndian, &size); err != nil || size != 2 {
			t.Fatal("invalid payload size", err)
		}
		var payload [2]byte
		if _, err := io.ReadFull(reader, payload[:]); err != nil {
			t.Fatal(err)
		}
		if seen[payload] {
			t.Fatal("duplicated payload")
		}
		seen[payload] = true
	}
	if reader.Len() != 0 {
		t.Fatal("trailing bytes")
	}
}

func TestXUDPReadBoundaryDeadlineCanRetry(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	target := M.ParseSocksaddr("127.0.0.1:53")
	conn := NewXUDPConn(left, [8]byte{}, target)
	left.SetReadDeadline(time.Now().Add(-time.Second))
	if p, _, err := conn.WaitReadPacket(); p != nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired read: %v %v", p, err)
	}
	left.SetReadDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, err := right.Write(muxTestFrame(StatusKeep, 0, []byte("next"), target)); done <- err }()
	p, d, err := conn.WaitReadPacket()
	if err != nil || d != target || string(p.Bytes()) != "next" {
		t.Fatalf("retry after deadline: %v %v", d, err)
	}
	p.Release()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestXUDPRejectsOversizedDomainBeforeWriting(t *testing.T) {
	destination := M.Socksaddr{Fqdn: string(bytes.Repeat([]byte{'x'}, 256)), Port: 53}
	client := NewXUDPConn(&frameReaderConn{Reader: bytes.NewReader(nil)}, [8]byte{}, destination)
	p := buf.NewSize(1)
	p.WriteByte(1)
	if err := client.WritePacket(p, destination); err == nil || p.RawCap() != 0 || !client.NeedHandshake() {
		t.Fatal("oversized destination accepted or retained")
	}
	server := &serverMuxPacketConn{session: &serverSession{}}
	p = buf.NewSize(1)
	p.WriteByte(1)
	if err := server.WritePacket(p, destination); err == nil || p.RawCap() != 0 {
		t.Fatal("oversized server destination accepted")
	}
	if _, err := server.session.syncWritePacket(0, []byte{1}, destination); err == nil {
		t.Fatal("oversized borrowed destination accepted")
	}
}
