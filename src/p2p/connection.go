package p2p

import (
	"github.com/xtaci/smux"
	"io"
	"net"
	"time"

	"akxsystem/src/config"
)

var c Conn

const MaxMessageSize = 4096

type Conn struct {
	net.Conn
	stream  *smux.Stream
	session *smux.Session
	Quit    chan bool
}

func (c *Conn) NewConn(conn net.Conn, p2pc *config.P2PConfig) (co Conn, err error) {
	co = Conn{
		Conn: conn,
	}
	err = conn.SetDeadline(time.Now().Add(time.Duration(p2pc.TimeoutInSeconds)))
	return
}

func SetupNewConnection(address string) error {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}

	session, err := smux.Client(conn, nil)
	if err != nil {
		return err
	}

	stream, err := session.OpenStream()

	co, err := c.NewConn(conn, &config.P2PConfig{TimeoutInSeconds: 60, MinPeers: 1, MaxPeers: 50, Version: []byte("1")})

	if err != nil {
		return err
	}

	co.Quit = make(chan bool)
	co.session = session
	co.stream = stream
	return nil
}

func SetupListener(hostAddress string) (addr string, stopFunc func(), client net.Conn, err error) {
	conn, err := net.Listen("tcp", hostAddress)
	if err != nil {
		return "", nil, nil, err
	}
	go func() {
		conn, err := conn.Accept()
		if err != nil {
			return
		}
		go ListenForNewConnections(conn)
	}()

	addr = conn.Addr().String()
	con, err := net.Dial("tcp", addr)
	if err != nil {
		return "", nil, nil, err
	}
	return conn.Addr().String(), func() { _ = conn.Close() }, con, nil

}

func ListenForNewConnections(conn net.Conn) {
	session, _ := smux.Server(conn, smux.DefaultConfig())
	for {
		if stream, err := session.AcceptStream(); err == nil {
			go func(s io.ReadWriteCloser) {
				buf := make([]byte, 65536)
				for {
					n, err := s.Read(buf)
					if err != nil {
						return
					}
					s.Write(buf[:n])
				}
			}(stream)
		} else {
			return
		}
	}
}
