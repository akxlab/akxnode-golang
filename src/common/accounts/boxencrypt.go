package accounts

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"github.com/cloudflare/circl/hpke"
	"github.com/umbracle/fastrlp"

	"akxsystem/src/utils"
)

type EncryptionBox struct {
	recipient *hpke.Receiver
	sender    *hpke.Sender
	Enc       []byte
	CT        []byte
	AAD       []byte
	PUBINFO   []byte
	suite     hpke.Suite
}

func (eBox *EncryptionBox) NewSharedEncryption(publicInfo string, extraData []byte, toEncryptPT []byte) *EncryptionBox {
	suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	info := []byte(publicInfo)

	eBox.suite = suite
	publicRecipient, privateRecipient, err := hpke.KEM_P256_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	recipient, err := suite.NewReceiver(privateRecipient, info)
	if err != nil {
		panic(err)
	}

	eBox.recipient = recipient

	sender, err := suite.NewSender(publicRecipient, info)
	if err != nil {
		panic(err)
	}

	eBox.sender = sender

	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		panic(err)
	}

	eBox.Enc = enc
	eBox.AAD = extraData

	ct, err := sealer.Seal(toEncryptPT, extraData)
	if err != nil {
		panic(err)
	}

	eBox.CT = ct

	return eBox
}

func (eBox *EncryptionBox) Decrypt(AAD []byte) []byte {
	opener, err := eBox.recipient.Setup(eBox.Enc)
	if err != nil {
		panic(err)
	}
	decrypted, err := opener.Open(eBox.CT, AAD)
	if err != nil {
		panic(err)
	}
	return decrypted

}

func NewEncryptionBox(AccountA, AccountB, AAD, toEncrypt []byte) *EncryptionBox {
	eBox := &EncryptionBox{}
	pubInfo := createPublicInfo(AccountA, AccountB)
	eBox.NewSharedEncryption(utils.EncodeToHex(pubInfo), AAD, toEncrypt)

	return eBox
}

func createPublicInfo(b ...[]byte) []byte {
	var ba [][]byte
	for i, bb := range b {
		ba[i] = bb
	}
	baj := bytes.Join(ba, nil)
	pubInfoHeader := []byte(`AKX Encrypted Box Message\n`)
	var ba2 [][]byte
	ba2[0] = pubInfoHeader
	ba2[1] = baj

	bafinal := bytes.Join(ba2, []byte("\n"))
	return bafinal
}

func PrepareEncryptionBoxForRecipient(eb *EncryptionBox) []byte {
	a := &fastrlp.Arena{}
	ebb, _ := json.Marshal(eb)
	bBox := a.NewBytes(ebb)
	buf := make([]byte, 4096)
	return bBox.MarshalTo(buf)
}

func ReceiveAndDecrypt(bbox []byte) []byte {
	a := &fastrlp.Parser{}
	parsed, _ := a.Parse(bbox)
	var eb EncryptionBox
	pb, _ := parsed.Bytes()
	err := json.Unmarshal(pb, &eb)
	if err != nil {
		panic(err)
	}

	ebI := &eb
	return ebI.Decrypt(ebI.AAD)
}
