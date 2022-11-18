package transaction

import (
	"math/big"
)

func (t *Transaction) SetGas() {
	t.GasData = &Gas{}
	t.GasData.Cost = new(big.Int).Mul(t.GasData.Price, new(big.Int).SetUint64(t.GasData.Consumption.Uint64()))
	t.GasData.Cost.Add(t.GasData.Cost, t.Value)
}

func (g *Gas) SetGasPrice(gasPrice *big.Int) {
	g.Price.Set(gasPrice)
}

func (t *Transaction) ConsumesMoreThanGasLimit(gasLimit uint64) bool {
	return t.GasData.Cost.Uint64() > gasLimit
}

func (t *Transaction) IsUnderpriced(priceLimit uint64) bool {
	return t.GasData.Price.Cmp(big.NewInt(0).SetUint64(priceLimit)) < 0
}
