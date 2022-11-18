package security

import (
	"errors"
	"github.com/benbjohnson/immutable"
)

type (
	algorithm struct {
		AlgBytes []byte
	}
	Algorithms struct {
		algs *immutable.Map[string, *algorithm]
	}
)

func (a *Algorithms) Get(name string) (*algorithm, error) {
	alg, exists := a.algs.Get(name)
	if !exists {
		return nil, errors.New("cannot get does not exists")
	}
	return alg, nil
}

func (a *Algorithms) Add(alg *algorithm, name string) bool {
	_, err := a.Get(name)
	if err == nil {
		return false
	}
	a.algs.Set(name, alg)
	return true

}

var Algorithm *Algorithms
var KXAlgorithms map[string]bool   // key exchange algorithms list
var SIGNAlgorithms map[string]bool // signature algorithms list
var ENCRYPTAlgs map[string]bool    // can encrypt algs

func init() {
	Algorithm = &Algorithms{
		algs: new(immutable.Map[string, *algorithm]),
	}

	Algorithm.Add(&algorithm{[]byte("KY")}, "KYBER")
	KXAlgorithms = make(map[string]bool)
	ENCRYPTAlgs = make(map[string]bool)
	ENCRYPTAlgs["KY"] = true
	KXAlgorithms["KY"] = true
	Algorithm.Add(&algorithm{[]byte("DL")}, "DILITHIUM")
	SIGNAlgorithms = make(map[string]bool)
	SIGNAlgorithms["DL"] = true
	Algorithm.Add(&algorithm{[]byte("R1")}, "RSA-2048")
	SIGNAlgorithms["R1"] = true
	Algorithm.Add(&algorithm{[]byte("R2")}, "RSA-1024")
	SIGNAlgorithms["R2"] = true
	Algorithm.Add(&algorithm{[]byte("R3")}, "RSA-512")
	SIGNAlgorithms["R3"] = true

}
