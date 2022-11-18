package utils

import (
	"hash"
	"sync"

	"github.com/umbracle/fastrlp"
	"golang.org/x/crypto/sha3"
)

type hashImpl interface {
	hash.Hash
	Read(b []byte) (int, error)
}

// Keccak is the sha256 keccak hash
type Keccak struct {
	buf  []byte // buffer to store intermediate rlp marshal values
	tmp  []byte
	hash hashImpl
}

// WriteRlp writes an RLP value
func (k *Keccak) WriteRlp(dst []byte, v *fastrlp.Value) []byte {
	k.buf = v.MarshalTo(k.buf[:0])
	k.Write(k.buf)

	return k.Sum(dst)
}

// Write implements the hash interface
func (k *Keccak) Write(b []byte) (int, error) {
	return k.hash.Write(b)
}

// Reset implements the hash interface
func (k *Keccak) Reset() {
	k.buf = k.buf[:0]
	k.hash.Reset()
}

// Read hashes the content and returns the intermediate buffer.
func (k *Keccak) Read() []byte {
	k.hash.Read(k.tmp)

	return k.tmp
}

// Sum implements the hash interface
func (k *Keccak) Sum(dst []byte) []byte {
	k.hash.Read(k.tmp)
	dst = append(dst, k.tmp[:]...)

	return dst
}

func newKeccak(hash hashImpl) *Keccak {
	return &Keccak{
		hash: hash,
		tmp:  make([]byte, hash.Size()),
	}
}

// NewKeccak256 returns a new keccak 256
func NewKeccak256() *Keccak {
	impl, ok := sha3.NewLegacyKeccak256().(hashImpl)
	if !ok {
		return nil
	}

	return newKeccak(impl)
}

// DefaultKeccakPool is a default pool
var DefaultKeccakPool Pool

// Pool is a pool of keccaks
type Pool struct {
	pool sync.Pool
}

// Get returns the keccak
func (p *Pool) Get() *Keccak {
	v := p.pool.Get()
	if v == nil {
		return NewKeccak256()
	}

	keccakVal, ok := v.(*Keccak)
	if !ok {
		return nil
	}

	return keccakVal
}

// Put releases the keccak
func (p *Pool) Put(k *Keccak) {
	k.Reset()
	p.pool.Put(k)
}

// Keccak256 hashes a src with keccak-256
func Keccak256(dst, src []byte) []byte {
	h := DefaultKeccakPool.Get()
	h.Write(src)
	dst = h.Sum(dst)
	DefaultKeccakPool.Put(h)

	return dst
}

// Keccak256Rlp hashes a fastrlp.Value with keccak-256
func Keccak256Rlp(dst []byte, src *fastrlp.Value) []byte {
	h := DefaultKeccakPool.Get()
	dst = h.WriteRlp(dst, src)
	DefaultKeccakPool.Put(h)

	return dst
}
