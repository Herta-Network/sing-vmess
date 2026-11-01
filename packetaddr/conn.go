package packetaddr

import (
	"net"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

var _ N.PacketReadWaitCreator = (*PacketConn)(nil)

type PacketConn struct {
	N.NetPacketConn
	bindAddr M.Socksaddr
}

func NewConn(conn net.PacketConn, bindAddr M.Socksaddr) *PacketConn {
	return &PacketConn{
		bufio.NewPacketConn(conn),
		bindAddr,
	}
}

func NewBindConn(conn net.Conn) *PacketConn {
	return &PacketConn{
		bufio.NewUnbindPacketConn(conn),
		M.Socksaddr{},
	}
}

func (c *PacketConn) RemoteAddr() net.Addr {
	return c.bindAddr
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *PacketConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.RemoteAddr())
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.With(p)
	var destination M.Socksaddr
	destination, err = c.ReadPacket(buffer)
	if err != nil {
		return
	}
	n = copy(p, buffer.Bytes())
	if destination.IsFqdn() {
		addr = destination
	} else {
		addr = destination.UDPAddr()
	}
	return
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return bufio.WritePacketBuffer(c, buf.As(p), M.SocksaddrFromNet(addr))
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	_, err = c.NetPacketConn.ReadPacket(buffer)
	if err != nil {
		return
	}
	destination, err = AddressSerializer.ReadAddrPort(buffer)
	if err != nil {
		return
	}
	return destination.Unwrap(), nil
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if destination.IsFqdn() {
		buffer.Release()
		return E.Extend(ErrFqdnUnsupported, destination.Fqdn)
	}
	header := buf.With(buffer.ExtendHeader(AddressSerializer.AddrPortLen(destination)))
	err := AddressSerializer.WriteAddrPortBuffer(header, destination)
	if err != nil {
		buffer.Release()
		return err
	}
	return c.NetPacketConn.WritePacket(buffer, c.bindAddr)
}

func (c *PacketConn) FrontHeadroom() int {
	return M.MaxIPSocksaddrLength
}

func (c *PacketConn) Upstream() any {
	return c.NetPacketConn
}

func (c *PacketConn) CreateReadWaiter() (N.PacketReadWaiter, bool) {
	prw, isReadWaiter := bufio.CreatePacketReadWaiter(c.NetPacketConn)
	if isReadWaiter {
		return &readWaiterPacketConn{
			readWaiter: prw,
			bindAddr:   c.bindAddr,
		}, true
	}
	return nil, false
}

var _ N.PacketReadWaiter = (*readWaiterPacketConn)(nil)

type readWaiterPacketConn struct {
	readWaiter N.PacketReadWaiter
	bindAddr   M.Socksaddr
}

func (c *readWaiterPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	return c.readWaiter.InitializeReadWaiter(options)
}

func (c *readWaiterPacketConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	buffer, _, err = c.readWaiter.WaitReadPacket()
	if err != nil {
		return
	}
	destination, err = AddressSerializer.ReadAddrPort(buffer)
	if err != nil {
		buffer.Release()
		return
	}
	destination = destination.Unwrap()
	return
}

func (c *readWaiterPacketConn) Upstream() any {
	return c.readWaiter
}
