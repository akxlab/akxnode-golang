package p2p

import (
	"bufio"
	"context"
)

type Transport interface {
	Name() string
	Version() []byte
	Reader() *bufio.Reader
	Writer() *bufio.Writer
	Context() context.Context
	Address() string
	NetworkID() []byte
}

type EncryptedTransport interface {
}

type SignedTransport interface {
}
