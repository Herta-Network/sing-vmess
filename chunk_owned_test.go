package vmess

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	N "github.com/metacubex/sing/common/network"
)

type chunkCipherSink struct {
	bytes.Buffer
	owned, borrowed int
	last            *buf.Buffer
}

func (s *chunkCipherSink) Write(p []byte) (int, error) { s.borrowed++; return s.Buffer.Write(p) }
func (s *chunkCipherSink) WriteBuffer(p *buf.Buffer) error {
	s.owned++
	s.last = p
	defer p.Release()
	_, err := s.Buffer.Write(p.Bytes())
	return err
}

func TestLargeOwnedCipherChunks(t *testing.T) {
	for _, security := range []byte{SecurityTypeLegacy, SecurityTypeAes128Gcm, SecurityTypeChacha20Poly1305} {
		options := []byte{RequestOptionChunkStream | RequestOptionChunkMasking | RequestOptionGlobalPadding}
		if security != SecurityTypeLegacy {
			options = append(options, RequestOptionChunkStream|RequestOptionAuthenticatedLength|RequestOptionGlobalPadding)
		}
		for _, option := range options {
			t.Run(fmt.Sprintf("security=%d/options=%d", security, option), func(t *testing.T) {
				sink := &chunkCipherSink{}
				key, nonce := make([]byte, 16), make([]byte, 16)
				writer := bufio.NewExtendedWriter(CreateWriter(sink, nil, key, nonce, key, nonce, security, option))
				reader := bufio.NewChunkReader(CreateReader(&sink.Buffer, nil, key, nonce, key, nonce, security, option), ReadChunkSize)
				for _, size := range []int{WriteChunkSize, WriteChunkSize + 1, 60000, 65535, 131072} {
					want := make([]byte, size)
					for i := range want {
						want[i] = byte(i)
					}
					packet := N.NewReadWaitOptions(nil, writer).NewBufferSize(size)
					packet.Write(want)
					N.NewReadWaitOptions(nil, writer).PostReturn(packet)
					if err := writer.WriteBuffer(packet); err != nil {
						t.Fatal(err)
					}
					if sink.last != packet || sink.borrowed != 0 {
						t.Fatalf("fell back to borrowed writes: %d", sink.borrowed)
					}
					got := make([]byte, size)
					if _, err := io.ReadFull(reader, got); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, want) {
						t.Fatal("chunk order or cipher mismatch")
					}
				}
			})
		}
	}
}
