package kyber

import (
	"bytes"
	"encoding/binary"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
	"io/ioutil"
	"os"
	"path"
	"strconv"

	"akxsystem/src/common/interfaces"
)

var pub [32]byte
var priv [32]byte

type Keys struct {
	interfaces.Keys
	Pub   []byte
	Priv  []byte
	Nonce uint
}

var tmpKeyBuffer map[uint]*Keys

var inMemoryKey []byte

var nonce uint

/*
GetPubKey() (interface{}, error)
	UsePrivateKey() (interface{}, error)
	UsePubKey() (interface{}, error)
	GenerateNewKeys(alg string) error
	GenerateNewKeysFromSeed(alg string, seed []byte) error
*/

func init() {
	loadNonce()
	tmpKeyBuffer = make(map[uint]*Keys)
	pub1, priv1 := LoadKeys()
	pubm, _ := pub1.MarshalBinary()
	skm, _ := priv1.MarshalBinary()
	copy(pub[:], pubm[:32])
	copy(priv[:], skm[:32])
}

func (k *Keys) GenerateNewKeys() (error, uint) {
	scheme := schemes.ByName("Kyber512")
	pk, sk, err := scheme.GenerateKeyPair()

	if err != nil {
		return err, 0
	}
	tmpKeyBuffer[nonce] = &Keys{}
	tmpKeyBuffer[nonce].Nonce = nonce
	_mNonce := tmpKeyBuffer[nonce].Nonce
	nonce++
	tmpKeyBuffer[_mNonce].Pub, _ = pk.MarshalBinary()
	tmpKeyBuffer[_mNonce].Priv, err = sk.MarshalBinary()
	err = saveNonce(_mNonce)
	err = writeKeyData(_mNonce)

	return err, _mNonce
}

func (k *Keys) GenerateNewKeysFromSeed(seed []byte) (error, uint) {
	pk, sk := schemes.ByName("Kyber512").DeriveKeyPair(seed)
	tmpKeyBuffer[nonce] = &Keys{}
	tmpKeyBuffer[nonce].Nonce = nonce
	_mNonce := tmpKeyBuffer[nonce].Nonce
	nonce++
	tmpKeyBuffer[_mNonce].Pub, _ = pk.MarshalBinary()
	tmpKeyBuffer[_mNonce].Priv, _ = sk.MarshalBinary()
	err := saveNonce(_mNonce)
	err = writeKeyData(_mNonce)
	return err, nonce
}

func (k *Keys) GetPubKey() (interface{}, error) {
	return k.Pub, nil
}

func (k *Keys) UsePrivateKey() (interface{}, error) {
	return nil, nil
}

func (k *Keys) UsePubKey() (interface{}, error) {
	return nil, nil
}

func saveNonce(mNonce uint) error {
	noncefilename := "./lastnonce.akx"
	buf := make([]byte, 32)
	binary.PutUvarint(buf, uint64(mNonce))
	err := ioutil.WriteFile(noncefilename, buf, 0600)
	return err

}

func writeKeyData(mNonce uint) error {
	fPath := interfaces.KEYS_PATH

	pubData := tmpKeyBuffer[mNonce].Pub
	privData := tmpKeyBuffer[mNonce].Priv

	fullPath := path.Join(fPath, "ky", strconv.Itoa(int(mNonce)))
	err := os.MkdirAll(fullPath, 0700)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path.Join(fullPath, "key.akx"), privData[:], 0600)
	err = ioutil.WriteFile(path.Join(fullPath, "pub.akx"), pubData[:], 0600)
	if err != nil {
		return err
	}
	return nil
}

func readKeyData(mNonce uint) (kem.PublicKey, error) {
	fPath := interfaces.KEYS_PATH
	fullPath := path.Join(fPath, "ky", strconv.Itoa(int(mNonce)))

	d, err := ioutil.ReadFile(path.Join(fullPath, "pub.akx"))
	if err != nil {
		panic(err)
	}

	return schemes.ByName("Kyber512").UnmarshalBinaryPublicKey(d[:800])

}

func readPrivKey(mNonce uint) (kem.PrivateKey, error) {
	fPath := interfaces.KEYS_PATH
	fullPath := path.Join(fPath, "ky", strconv.Itoa(int(mNonce)))

	d, _ := ioutil.ReadFile(path.Join(fullPath, "key.akx"))
	return schemes.ByName("Kyber512").UnmarshalBinaryPrivateKey(d[:])
}

func LoadKeys() (kem.PublicKey, kem.PrivateKey) {
	_n := loadNonce()

	keyDataPub, err := readKeyData(_n)

	if err != nil {
		panic(err)
	}
	keyDataPriv, err := readPrivKey(_n)
	if err != nil {
		panic(err)
	}

	return keyDataPub, keyDataPriv
}

func loadNonce() uint {
	mNonce, err := os.ReadFile("./lastnonce.akx")
	if err == os.ErrNotExist {
		saveNonce(uint(0))
		mNonce, _ = os.ReadFile("./lastnonce.akx")
	}
	buf := bytes.NewReader(mNonce)
	_n, _ := binary.ReadUvarint(buf)

	return uint(_n)
}

func checkIfNewNonce() bool {
	_, err := os.ReadFile("./lastnonce.akx")
	if err != nil && err == os.ErrNotExist {
		return true
	}
	return false
}

func NewKeys() (err error) {
	if checkIfNewNonce() {
		nonce = 1
	} else {
		_nonce := loadNonce()
		nonce = _nonce + 1
	}
	keys := &Keys{}
	/*if bytes.Compare(seed, []byte(nil)) != 0 {
		err, _ = keys.GenerateNewKeysFromSeed(seed)
	} else {*/
	err, _ = keys.GenerateNewKeys()
	//}
	tmpKeyBuffer[nonce] = &Keys{}
	if err != nil {
		return
	}
	return nil
}

func GetPublic() [32]byte {
	return pub
}
