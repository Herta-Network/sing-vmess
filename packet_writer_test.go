package vmess

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func TestUDPLargePacketIsOneCipherRecord(t *testing.T) {
	for _, security := range []byte{SecurityTypeNone, SecurityTypeLegacy, SecurityTypeAes128Gcm, SecurityTypeChacha20Poly1305} {
		for _, option := range []byte{RequestOptionChunkStream, RequestOptionChunkStream | RequestOptionChunkMasking | RequestOptionGlobalPadding} {
			var encoded bytes.Buffer
			key, nonce := make([]byte, 16), make([]byte, 16)
			writer := bufio.NewExtendedWriter(CreateWriter(&encoded, nil, key, nonce, key, nonce, security, option))
			payloads := [][]byte{bytes.Repeat([]byte{0x53}, 60000), []byte("tail")}
			if security != SecurityTypeNone {
				payloads = append(payloads, nil)
			}
			for _, payload := range payloads {
				b := N.NewReadWaitOptions(nil, writer).Copy(buf.As(payload))
				if err := validatePacket(b, security); err != nil {
					b.Release()
					t.Fatal(err)
				}
				if err := writePacketBuffer(writer, b); err != nil {
					t.Fatal(err)
				}
			}
			reader := bufio.NewExtendedReader(CreateReader(bytes.NewReader(encoded.Bytes()), nil, key, nonce, key, nonce, security, option))
			for _, want := range payloads {
				b := buf.NewSize(65535)
				err := reader.ReadBuffer(b)
				if err != nil || !bytes.Equal(b.Bytes(), want) {
					t.Fatalf("security=%d option=%d length=%d want=%d err=%v", security, option, b.Len(), len(want), err)
				}
				b.Release()
			}
		}
	}
}

type failedPacketConn struct{ net.Conn }

func (*failedPacketConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestUDPLazyResponseErrorReleasesBuffer(t *testing.T) {
	conn := &serverPacketConn{rawServerConn: rawServerConn{Conn: &failedPacketConn{}, security: SecurityTypeAes128Gcm, requestKey: make([]byte, 16), requestNonce: make([]byte, 16)}}
	b := buf.NewSize(1)
	b.WriteByte(1)
	if err := conn.WritePacket(b, M.Socksaddr{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if b.RawCap() != 0 {
		t.Fatal("failed response retained payload")
	}
}

type frameReaderConn struct {
	net.Conn
	*bytes.Reader
}

func (c *frameReaderConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }
func TestXUDPEmptyPacketIsDelivered(t *testing.T) {
	destination := M.ParseSocksaddr("127.0.0.1:5353")
	var frame bytes.Buffer
	binary.Write(&frame, binary.BigEndian, uint16(5+AddressSerializer.AddrPortLen(destination)))
	binary.Write(&frame, binary.BigEndian, uint16(1))
	frame.WriteByte(StatusKeep)
	frame.WriteByte(OptionData)
	frame.WriteByte(NetworkUDP)
	if err := AddressSerializer.WriteAddrPort(&frame, destination); err != nil {
		t.Fatal(err)
	}
	binary.Write(&frame, binary.BigEndian, uint16(0))
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	session := &serverSession{conn: &frameReaderConn{Reader: bytes.NewReader(frame.Bytes())}, streams: map[uint16]*serverStream{1: {network: NetworkUDP, destination: destination, pipe: writer}}}
	done := make(chan error, 1)
	go func() { done <- session.recv() }()
	got := make(chan error, 1)
	go func() {
		conn := &serverMuxPacketConn{pipe: reader}
		b := buf.NewSize(1)
		defer b.Release()
		addr, err := conn.ReadPacket(b)
		if err == nil && (addr != destination || !b.IsEmpty()) {
			err = errors.New("empty packet lost destination")
		}
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("empty XUDP packet was discarded")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type shortResponseConn struct{ net.Conn }

func (*shortResponseConn) Write([]byte) (int, error) { return 1, nil }
func TestUDPLazyResponseRejectsShortSuccess(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		conn := &serverPacketConn{rawServerConn: rawServerConn{Conn: &shortResponseConn{}, legacyProtocol: legacy, security: SecurityTypeAes128Gcm, requestKey: make([]byte, 16), requestNonce: make([]byte, 16)}}
		b := buf.NewSize(1)
		b.WriteByte(1)
		if err := conn.WritePacket(b, M.Socksaddr{}); !errors.Is(err, io.ErrShortWrite) {
			t.Fatal(err)
		}
		if b.RawCap() != 0 {
			t.Fatal("short header retained payload")
		}
	}
}
