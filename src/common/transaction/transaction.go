package transaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/umbracle/fastrlp"
	"lukechampine.com/blake3"
	"math/big"

	"akxsystem/src/common/types"
	"akxsystem/src/security/kyber"
)

func NewTransaction(to string, from string, value *big.Int, nonce uint64) (*Transaction, error) {

	toaddr := types.StringToAddress(to)
	fromaddr := types.StringToAddress(from)
	tx := &Transaction{}
	tx.Nonce = nonce
	tx.To = &toaddr
	tx.From = fromaddr
	tx.Value = value
	tx.SetVRS()
	tx.SetGas()
	tx.SetHash()
	return tx, nil
}

func (t *Transaction) IsContractTx() bool {
	return t.From.Bytes() == nil
}

func (t *Transaction) SetHash() {
	var key []byte
	pub := kyber.GetPublic()
	copy(key[:], pub[:])
	t.Hash = calculateTxHash(t, key)
}

func calculateTxHash(tx *Transaction, key []byte) []byte {
	hasher := blake3.New(64, key)
	j, _ := json.Marshal(tx)
	_, _ = hasher.Write(j)
	_, _ = hasher.Write(tx.vrs.V.Bytes())
	return hasher.Sum(nil)

}

func VerifyTxHash(tx *Transaction) error {

	var key []byte
	pub := kyber.GetPublic()
	copy(key[:], pub[:])
	hash := calculateTxHash(tx, key)
	if bytes.Compare(hash, tx.Hash) != 0 {
		return errors.New("tx hash is invalid")
	}
	return nil

}

func (t *Transaction) SetVRS() {
	a := &fastrlp.Arena{}
	v := a.NewBytes(t.From.Bytes())
	buf := v.MarshalTo(nil)
	t.vrs.V.SetBytes(buf)
	t.vrs.R.Set(big.NewInt(0).SetBits(t.Value.Bits()))
	t.vrs.S.Set(big.NewInt(0).SetBits(t.vrs.V.Add(t.vrs.R, nil).Bits()))
}

func (t *Transaction) MarshalRLP() *fastrlp.Value {

	a := &fastrlp.Arena{}
	vv := a.NewArray()
	vv.Set(a.NewUint(t.Nonce))
	vv.Set(a.NewBigInt(t.GasData.Price))
	vv.Set(a.NewUint(t.GasData.Cost.Uint64()))
	if !t.IsContractTx() {
		vv.Set(a.NewBytes((*t.To).Bytes()))
	} else {
		vv.Set(a.NewNull())
	}

	vv.Set(a.NewBigInt(t.Value))
	vv.Set(a.NewCopyBytes(t.Input))

	vv.Set(a.NewBigInt(t.vrs.V))
	vv.Set(a.NewBigInt(t.vrs.R))
	vv.Set(a.NewBigInt(t.vrs.S))

	return vv

}
