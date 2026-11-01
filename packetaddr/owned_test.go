package packetaddr

import (
	"bytes"
	"net"
	"testing"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type ownedPacketSink struct {
	N.NetPacketConn
	wire    []byte
	input   *buf.Buffer
	inPlace bool
}

func (s *ownedPacketSink) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	defer b.Release()
	s.inPlace = b == s.input
	s.wire = append(s.wire[:0], b.Bytes()...)
	return nil
}
func (s *ownedPacketSink) WriteTo(p []byte, _ net.Addr) (int, error) {
	s.wire = append(s.wire[:0], p...)
	return len(p), nil
}

func TestOwnedPacketAndBorrowedCount(t *testing.T) {
	sink := &ownedPacketSink{}
	conn := NewConn(sink, M.ParseSocksaddr("127.0.0.1:443"))
	target := M.ParseSocksaddr("[2001:db8::1]:53")
	for _, payload := range [][]byte{nil, []byte("payload")} {
		packet := N.NewReadWaitOptions(nil, conn).Copy(buf.As(payload))
		sink.input = packet
		if err := conn.WritePacket(packet, target); err != nil {
			t.Fatal(err)
		}
		if !sink.inPlace || packet.RawCap() != 0 {
			t.Fatal("owned packet copied or retained")
		}
		wantWire := append([]byte(nil), sink.wire...)
		original := append([]byte(nil), payload...)
		n, err := conn.WriteTo(payload, target)
		if err != nil || n != len(payload) || !bytes.Equal(payload, original) || !bytes.Equal(sink.wire, wantWire) {
			t.Fatalf("borrowed count=%d err=%v", n, err)
		}
	}
	for _, target := range []M.Socksaddr{{}, M.ParseSocksaddr("example.com:53")} {
		packet := buf.NewSize(40)
		packet.Resize(32, 1)
		if err := conn.WritePacket(packet, target); err == nil || packet.RawCap() != 0 {
			t.Fatal("rejected packet retained")
		}
	}
}
