package accounts

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"github.com/cloudflare/circl/pke/kyber/kyber512"

	"github.com/cloudflare/circl/sign/eddilithium2"
	"go.uber.org/atomic"
	"io/ioutil"
	"math/big"
	"os"

	"akxsystem/src/common/interfaces"
	"akxsystem/src/common/types"
	"akxsystem/src/utils"
)

const ACCT_KEYSTORE_PATH = "./.keystore/a/"

type Account struct {
	Address    types.Address
	Balance    *big.Int
	Nonce      atomic.Uint32
	SKID       uint32
	LoadedSKey eddilithium2.PrivateKey
	LoadedPub  eddilithium2.PublicKey
	Pub        []byte
	Priv       []byte
}

type AccountFile struct {
	Address types.Address
	Nonce   uint32
	SKID    uint32
	Pub     []byte
	Priv    []byte
}

func NewAccount() string {
	a := &Account{}
	a.Nonce.Store(0)
	a.GenKeys()
	//a.GetSignKey(0)

	pk, sk, _ := kyber512.GenerateKey(rand.Reader)
	packedPk := make([]byte, kyber512.PublicKeySize)
	packedSk := make([]byte, kyber512.PrivateKeySize)
	pk.Pack(packedPk)

	a.Pub = packedPk
	sk.Pack(packedSk)
	a.Priv = packedSk
	addrBytes := a.Pub[:20]
	addr := []byte(utils.EncodeToHex(addrBytes[:20]))
	var abt [20]byte
	copy(abt[:], addr[:])
	k := utils.NewKeccak256()
	k.Write(addr[:])
	a.Address = abt
	a.Balance = big.NewInt(0)

	addrhash := k.Sum(nil)

	a.Address = types.BytesToAddress(addrhash)

	af := &AccountFile{}
	af.Address = types.BytesToAddress(addrhash)
	af.Nonce = a.Nonce.Load()
	af.SKID = a.SKID
	af.Pub = a.Pub
	af.Priv = a.Priv

	aBytes, _ := json.Marshal(af)
	os.MkdirAll("./.keystore/accounts/", 0700)
	_ = ioutil.WriteFile("./.keystore/accounts/"+af.Address.String(), aBytes, 0600)
	return a.Address.String()

}

func (a *Account) GenKeys() {
	ak := &accountKeys{}
	ak.GenerateSignKey()
	a.SKID = a.Nonce.Load()
	a.Nonce.Inc()
}

func (a *Account) GetSignKey(id uint32) {
	s := &SignKey{}
	sk, pk, err := s.Read(uint(id))
	if err != nil {
		panic(err)
	}
	a.LoadedSKey = sk
	a.LoadedPub = pk.(eddilithium2.PublicKey)

}

func (a *Account) Sign(msg []byte) ([]byte, error) {
	sig, err := a.LoadedSKey.Sign(rand.Reader, msg, crypto.SHA3_256)
	return sig, err

}

func (a *Account) VerifySig(msg []byte, sig []byte) bool {
	a.GetSignKey(a.SKID)
	pub := a.LoadedPub
	v := pub.Scheme().Verify(&a.LoadedPub, msg, sig, nil)
	return v == true
}

type accountKeys struct {
	S   *SignKey        // sign key
	E   interfaces.Keys // encryption key
	KX  interfaces.Keys // key exchange key
	SHK []byte          // shared key
}

type AKeys interface {
	Generate() *SignKey
}

func getAccountKeys(seed []byte) *accountKeys {
	ak := &accountKeys{}
	return ak
}

func (ak *accountKeys) GenerateSignKey() {
	s := &SignKey{}
	ak.S = s.Generate()
}
