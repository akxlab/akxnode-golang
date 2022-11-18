package transports

import (
	"bufio"
	"context"
	"github.com/xtaci/smux"
	"net"

	"akxsystem/src/p2p"
)

func NewTransport(ver []byte, ctx context.Context, address string, netId []byte) p2p.Transport {
	return &TCPTransport{version: ver, ctx: ctx, address: address, networkId: netId}
}

type TCPTransport struct {
	Dialer    net.Dialer
	Mux       *smux.Session
	C         net.TCPConn
	L         net.TCPListener
	version   []byte
	reader    *bufio.Reader
	writer    *bufio.Writer
	ctx       context.Context
	address   string
	networkId []byte
}

func (T *TCPTransport) Name() string {
	return "tcp"
}

func (T *TCPTransport) Version() []byte {
	return T.version
}

func (T *TCPTransport) Reader() *bufio.Reader {
	return T.reader
}

func (T *TCPTransport) Writer() *bufio.Writer {
	return T.writer
}

func (T *TCPTransport) Context() context.Context {
	return T.ctx
}

func (T *TCPTransport) Address() string {
	return T.address
}

func (T *TCPTransport) NetworkID() []byte {
	return T.networkId
}
