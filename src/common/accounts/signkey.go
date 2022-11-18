package accounts

import (
	"crypto"
	signAlg "github.com/cloudflare/circl/sign/eddilithium2"
	"io/ioutil"
	"path"

	"akxsystem/src/common/osf"
	"akxsystem/src/utils"
)

var SIGN_KEY_PATH = path.Join(ACCT_KEYSTORE_PATH, "s")

type SignKey struct {
	pub *signAlg.PublicKey
	sk  *signAlg.PrivateKey
	psk *[signAlg.PrivateKeySize]byte
	ppk *[signAlg.PublicKeySize]byte
	P   []byte // 32 first bytes of pub key
	SK  []byte // 32 first bytes of priv key
}

func (s *SignKey) Generate() *SignKey {
	pk, sk, err := signAlg.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	s.pub = pk
	s.sk = sk
	s.psk, s.ppk = packSignKey(sk, pk)
	s.P = s.ppk[:32]
	s.SK = s.psk[:32]
	s.Store(0)
	return s
}

func (s *SignKey) Store(id uint) error {

	file := &osf.OSFSFile{}
	f, _ := file.New(osf.FILE_FLAG_RAW)
	f.SetData(s.psk[:])
	fp := path.Join(SIGN_KEY_PATH, utils.EncodeUint64(uint64(id)))
	err := f.Write(fp, utils.EncodeUint64(uint64(id))+"_key")
	if err != nil {
		return err
	}
	return nil
}

func (s *SignKey) Read(id uint) (signAlg.PrivateKey, crypto.PublicKey, error) {
	fp := path.Join(SIGN_KEY_PATH, utils.EncodeUint64(uint64(id)))
	fileName := utils.EncodeUint64(uint64(id)) + "_key"
	f, _ := ioutil.ReadFile(path.Join(fp, fileName))

	data := osf.DecodeToFilePacket(f)
	var bData [signAlg.PrivateKeySize]byte
	copy(bData[:], data[:])
	sk, pk := unpackSignKey(bData)
	return sk, pk, nil
}

func packSignKey(sk *signAlg.PrivateKey, pk *signAlg.PublicKey) (*[signAlg.PrivateKeySize]byte,
	*[signAlg.PublicKeySize]byte) {

	var packedSk [signAlg.PrivateKeySize]byte
	var packedPk [signAlg.PublicKeySize]byte
	sk.Pack(&packedSk)
	pk.Pack(&packedPk)
	return &packedSk, &packedPk
}

func unpackSignKey(packedSk [signAlg.PrivateKeySize]byte) (signAlg.PrivateKey,
	crypto.PublicKey) {
	var sk2 signAlg.PrivateKey

	sk2.Unpack(&packedSk)
	pk2 := sk2.Public()
	return sk2, pk2
}
