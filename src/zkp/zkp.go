package zkp

import (
	"errors"
	"go.uber.org/atomic"
)

type Proofer struct {
	Z     *ZKP
	Data  map[uint]ProoferData
	Nonce atomic.Uint32
}

type ProoferData struct {
	Inputs  [][]byte
	Outputs [][]byte
	Valid   bool
}

func NewZKP() *ZKP {
	z := &ZKP{}
	z.Setup()
	return z
}

func GetProofer() *Proofer {
	p := NewProofer(NewZKP())
	return p
}

func NewProofer(z *ZKP) *Proofer {
	p := &Proofer{Z: z, Data: make(map[uint]ProoferData)}
	p.Nonce.Store(0)
	return p
}

func (p *Proofer) GenerateOutputs(inputs ...[]byte) error {

	nonce := p.Nonce.Load()
	nonce = uint32(uint(nonce))

	done, outputs := p.Z.ZkpIT(inputs)
	if done {

		if len(outputs) == len(inputs) {

			for i, ib := range inputs {
				p.Data[uint(nonce)].Inputs[i] = ib
				p.Data[uint(nonce)].Outputs[i] = outputs[i]
			}
		} else {
			return errors.New("invalid inputs / outputs proof")
		}
	} else {
		return errors.New("invalid inputs / outputs proof")
	}

	p.Nonce.Inc()

	return nil

}
