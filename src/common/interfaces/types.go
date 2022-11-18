package interfaces

import (
	"akxsystem/src/security"
)

const KEYS_PATH string = "./.keystore/"

type Security interface {
	Algs() *security.Algorithms
	KxAlgs() []string
	EncAlgs() []string
	SignAlgs() []string
}

type Keys interface {
	GetPubKey() (interface{}, error)
	UsePrivateKey() (interface{}, error)
	UsePubKey() (interface{}, error)
	GenerateNewKeys() (error, uint)
	GenerateNewKeysFromSeed(seed []byte) (error, uint)
}
