package vmess

import (
	"errors"
	"io"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	N "github.com/metacubex/sing/common/network"
)

// Leave room for the worst-case authentication/padding overhead in the
// protocol's uint16 length field. TCP chunking must not split a UDP datagram.
const MaxPacketPayload = 65535 - MaxRearHeadroom

func validatePacket(buffer *buf.Buffer, security byte) error {
	if buffer.Len() > MaxPacketPayload {
		return io.ErrShortBuffer
	}
	if buffer.IsEmpty() && security == SecurityTypeNone {
		return errors.New("VMess UDP without encryption cannot encode an empty datagram")
	}
	return nil
}
func writePacketBuffer(writer N.ExtendedWriter, buffer *buf.Buffer) error {
	// CreateWriter places this one TCP-only chunk limiter outside the cipher.
	// Keep every cipher, length mask and padding layer below it intact.
	if chunkWriter, ok := writer.(*bufio.ChunkWriter); ok {
		writer = bufio.NewExtendedWriter(chunkWriter.Upstream().(io.Writer))
	}
	return writer.WriteBuffer(buffer)
}
