package vmess

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type ownedCipherSink struct {
	net.Conn
	bytes.Buffer
	input           *buf.Buffer
	owned, borrowed int
}

func (s *ownedCipherSink) Read(p []byte) (int, error) { return s.Buffer.Read(p) }

func (s *ownedCipherSink) Write(p []byte) (int, error) { s.borrowed++; return s.Buffer.Write(p) }
func (s *ownedCipherSink) WriteBuffer(b *buf.Buffer) error {
	defer b.Release()
	if b != s.input {
		return io.ErrUnexpectedEOF
	}
	s.owned++
	_, err := s.Buffer.Write(b.Bytes())
	return err
}

func TestOwnedCipherChainKeepsBuffer(t *testing.T) {
	for _, security := range []byte{SecurityTypeLegacy, SecurityTypeAes128Gcm, SecurityTypeChacha20Poly1305} {
		options := []byte{RequestOptionChunkStream | RequestOptionChunkMasking | RequestOptionGlobalPadding}
		if security != SecurityTypeLegacy {
			options = append(options, RequestOptionChunkStream|RequestOptionAuthenticatedLength|RequestOptionGlobalPadding)
		}
		for _, option := range options {
			sink := &ownedCipherSink{}
			key, nonce := make([]byte, 16), make([]byte, 16)
			writer := bufio.NewExtendedWriter(CreateWriter(sink, nil, key, nonce, key, nonce, security, option))
			reader := bufio.NewExtendedReader(CreateReader(&sink.Buffer, nil, key, nonce, key, nonce, security, option))
			for _, size := range []int{0, 1, 1200, 60000} {
				payload := bytes.Repeat([]byte{0x47}, size)
				packet := N.NewReadWaitOptions(nil, writer).Copy(buf.As(payload))
				sink.input = packet
				if err := writePacketBuffer(writer, packet); err != nil {
					t.Fatal(err)
				}
				if packet.RawCap() != 0 || sink.borrowed != 0 {
					t.Fatalf("security=%d buffer not transferred: borrowed=%d", security, sink.borrowed)
				}
				decoded := buf.NewSize(65535)
				if err := reader.ReadBuffer(decoded); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(decoded.Bytes(), payload) {
					t.Fatal("cipher framing changed")
				}
				decoded.Release()
			}
			if sink.owned != 4 {
				t.Fatal("lost record")
			}
		}
	}
}

func TestXUDPOwnedHeadersAndValidation(t *testing.T) {
	target := M.ParseSocksaddr("[2001:db8::1]:5353")
	for _, globalID := range [][8]byte{{}, {1, 2, 3, 4, 5, 6, 7, 8}} {
		sink := &ownedCipherSink{}
		conn := NewXUDPConn(sink, globalID, target)
		for index, payload := range [][]byte{nil, []byte("later")} {
			packet := N.NewReadWaitOptions(nil, conn).Copy(buf.As(payload))
			sink.input = packet
			if err := conn.WritePacket(packet, target); err != nil {
				t.Fatal(err)
			}
			wire := sink.Bytes()
			length := int(binary.BigEndian.Uint16(wire))
			wantStatus := byte(StatusNew)
			if index != 0 {
				wantStatus = StatusKeep
			}
			if wire[4] != wantStatus || wire[5] != OptionData || wire[6] != NetworkUDP {
				t.Fatal("XUDP flags changed")
			}
			addressReader := bytes.NewReader(wire[7 : 2+length])
			got, err := AddressSerializer.ReadAddrPort(addressReader)
			if err != nil || got != target {
				t.Fatalf("address=%v err=%v", got, err)
			}
			if index == 0 && globalID != [8]byte{} {
				var gotID [8]byte
				if _, err := io.ReadFull(addressReader, gotID[:]); err != nil || gotID != globalID {
					t.Fatal("global ID lost")
				}
			}
			if addressReader.Len() != 0 || int(binary.BigEndian.Uint16(wire[2+length:])) != len(payload) || !bytes.Equal(wire[4+length:], payload) {
				t.Fatal("XUDP length changed")
			}
			sink.Reset()
		}
	}
	for _, size := range []int{1, 65536} {
		sink := &ownedCipherSink{}
		conn := NewXUDPConn(sink, [8]byte{}, target)
		packet := buf.NewSize(300 + size)
		packet.Resize(300, size)
		if err := conn.WritePacket(packet, M.Socksaddr{}); err == nil || packet.RawCap() != 0 || !conn.NeedHandshake() {
			t.Fatal("invalid packet retained or advanced handshake")
		}
	}
}
