package vmess

import (
	"encoding/binary"
	"io"
	"net"

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
	requestWritten  bool
	globalID        [8]byte
	readWaitOptions N.ReadWaitOptions
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

func (c *XUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.With(p)
	var destination M.Socksaddr
	destination, err = c.ReadPacket(buffer)
	if err != nil {
		return
	}
	if destination.IsFqdn() {
		addr = destination
	} else {
		addr = destination.UDPAddr()
	}
	n = buffer.Len()
	return
}

func (c *XUDPConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	start := buffer.Start()
	_, err = buffer.ReadFullFrom(c.Conn, 6)
	if err != nil {
		return
	}
	var length uint16
	err = binary.Read(buffer, binary.BigEndian, &length)
	if err != nil {
		return
	}
	header, err := buffer.ReadBytes(4)
	if err != nil {
		return
	}
	switch header[2] {
	case StatusNew:
		return M.Socksaddr{}, E.New("unexpected frame new")
	case StatusKeep:
		if length != 4 {
			_, err = buffer.ReadFullFrom(c.Conn, int(length)-2)
			if err != nil {
				return
			}
			buffer.Advance(1)
			destination, err = AddressSerializer.ReadAddrPort(buffer)
			if err != nil {
				return
			}
			destination = destination.Unwrap()
		} else {
			_, err = buffer.ReadFullFrom(c.Conn, 2)
			if err != nil {
				return
			}
			destination = c.destination
		}
	case StatusEnd:
		return M.Socksaddr{}, io.EOF
	case StatusKeepAlive:
	default:
		return M.Socksaddr{}, E.New("unexpected frame: ", buffer.Byte(2))
	}
	// option error
	if header[3]&2 == 2 {
		return M.Socksaddr{}, E.Cause(net.ErrClosed, "remote closed")
	}
	// option data
	if header[3]&1 != 1 {
		buffer.Resize(start, 0)
		return c.ReadPacket(buffer)
	} else {
		err = binary.Read(buffer, binary.BigEndian, &length)
		if err != nil {
			return
		}
		buffer.Resize(start, 0)
		_, err = buffer.ReadFullFrom(c.Conn, int(length))
		return
	}
}

func (c *XUDPConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	return false
}

func (c *XUDPConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	var header [6]byte
	_, err = io.ReadFull(c.Conn, header[:])
	if err != nil {
		return
	}
	length := binary.BigEndian.Uint16(header[:])
	if err != nil {
		return
	}
	switch header[4] {
	case StatusNew:
		return nil, M.Socksaddr{}, E.New("unexpected frame new")
	case StatusKeep:
		buffer = c.readWaitOptions.NewPacketBuffer()
		if length != 4 {
			start := buffer.Start()
			_, err = buffer.ReadFullFrom(c.Conn, int(length)-4)
			if err != nil {
				buffer.Release()
				return
			}
			buffer.Advance(1)
			destination, err = AddressSerializer.ReadAddrPort(buffer)
			if err != nil {
				buffer.Release()
				return
			}
			destination = destination.Unwrap()
			buffer.Resize(start, 0)
		} else {
			destination = c.destination
		}
	case StatusEnd:
		return nil, M.Socksaddr{}, io.EOF
	case StatusKeepAlive:
		buffer = c.readWaitOptions.NewPacketBuffer()
	default:
		return nil, M.Socksaddr{}, E.New("unexpected frame: ", header[4])
	}
	// option error
	if header[5]&2 == 2 {
		buffer.Release()
		return nil, M.Socksaddr{}, E.Cause(net.ErrClosed, "remote closed")
	}
	// option data
	if header[5]&1 != 1 {
		destination, err = c.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
		}
		c.readWaitOptions.PostReturn(buffer)
		return
	} else {
		err = binary.Read(c.Conn, binary.BigEndian, &length)
		if err != nil {
			buffer.Release()
			return
		}
		_, err = buffer.ReadFullFrom(c.Conn, int(length))
		if err != nil {
			buffer.Release()
		}
		c.readWaitOptions.PostReturn(buffer)
		return
	}
}

func (c *XUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return bufio.WritePacketBuffer(c, buf.As(p), M.SocksaddrFromNet(addr))
}

func (c *XUDPConn) frontHeadroom(addrLen int) int {
	if !c.requestWritten {
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
	dataLen := buffer.Len()
	if dataLen > 65535 || !destination.IsValid() {
		buffer.Release()
		return E.New("invalid XUDP packet")
	}
	addrLen := M.SocksaddrSerializer.AddrPortLen(destination)
	if !c.requestWritten {
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
		c.requestWritten = true
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
	return c.writer.WriteBuffer(buffer)
}

func (c *XUDPConn) FrontHeadroom() int {
	return c.frontHeadroom(M.MaxSocksaddrLength)
}

func (c *XUDPConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *XUDPConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *XUDPConn) Upstream() any {
	return c.Conn
}
