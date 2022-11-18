package osf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"sync"
)

// common IO file system

type RawFile struct {
	rawData []byte
}

type EncFile struct {
	_encData []byte
	_hash    []byte
	_sig     []byte
}

type DecFile struct {
	*RawFile
}

type OSFS struct {
	tmpBuffer     map[uint][]byte
	tmpDecBuffer  map[uint][]byte
	tmpFileBuffer map[uint][]byte
	mu            *sync.Mutex
	FileID        string
	FileName      string
	FilePath      string
	EncKeyID      uint
	DecKeyID      uint
	SigKeyID      uint
	work          []byte
}

type OSFSFile struct {
	Flags     []FileFlag
	Data      []byte
	Size      uint
	Signature []byte
	H         []byte
}

type FileFlag uint16

type FileData struct{}

const PREFIX uint32 = 0x616b66 // byte("akf") file starts with those bytes to validate it can be processed as an AKX file format

const FILE_FLAG_ENCRYPTED FileFlag = 0x0ef1
const FILE_FLAG_RAW FileFlag = 0x0ef2
const FILE_FLAG_LOCKED FileFlag = 0x0ef3

func NewOSFS() *OSFS {
	osfs := &OSFS{}
	osfs.tmpBuffer = map[uint][]byte{}
	osfs.tmpDecBuffer = map[uint][]byte{}
	osfs.tmpFileBuffer = map[uint][]byte{}
	return osfs
}

func (o *OSFS) setKeyIDS(ek, dk, sk uint) {
	o.EncKeyID = ek
	o.DecKeyID = dk
	o.SigKeyID = sk
}

func (o *OSFS) setWork(w []byte) {
	o.work = w
}

func (o *OSFS) setFileData(fileID, fileName, filePath string) {
	o.FileID = fileID
	o.FileName = fileName
	o.FilePath = filePath
}

func (f *OSFSFile) New(ff ...FileFlag) (*OSFSFile, error) {

	ffl := len(ff)
	if ffl > 3 {
		return nil, errors.New("too many flags given to file")
	}
	for _, flg := range ff {
		f.Flags = append(f.Flags, flg)
	}

	return f, nil
}

func (f *OSFSFile) SetData(_data []byte) {
	f.Data = _data

}

func (f *OSFSFile) Encode() []byte {

	buf := bytes.NewBuffer(nil)

	b := make([]byte, 6+(len(f.Flags)*2))

	binary.BigEndian.PutUint32(b, PREFIX) // prefix is 4 byte (uint32)
	binary.BigEndian.PutUint16(b, uint16(len(f.Flags)))
	var index int
	for i, flg := range f.Flags {
		if i == 0 {
			index = 4
		} else {
			index = index + 2
		}
		binary.BigEndian.PutUint16(b[index:], uint16(flg)) // each flag  is 2 byte (uint16)
	}

	b1 := make([]byte, 8)
	binary.BigEndian.PutUint16(b1, uint16(0xaddd)) // data separator

	binary.BigEndian.PutUint32(b1, uint32(f.Size))

	binary.BigEndian.PutUint16(b1, uint16(0xaddd)) // data separator

	b2 := make([]byte, 2)

	_ = binary.Write(buf, binary.LittleEndian, f.Data)

	binary.BigEndian.PutUint16(b2, uint16(0xafff))

	bBytes := make([][]byte, 4)

	bBytes[0] = b
	bBytes[1] = b1
	bBytes[2] = buf.Bytes()
	bBytes[3] = b2

	bb := bytes.Join(bBytes, nil)

	return bb

}

func (f *OSFSFile) Write(filePath, fileName string) error {
	data := f.Encode()
	_ = os.MkdirAll(filePath, 0750)
	err := ioutil.WriteFile(path.Join(filePath, fileName+".akf"), data, 0644)
	if err != nil {
		panic(err)
	}
	return nil
}

func (f *OSFSFile) WriteEncrypted(sk []byte) {

}

type FilePacket struct {
	prefix uint32
	flags  []uint16
	size   uint32
	data   []byte
	bits   []big.Word
}

func DecodeToFilePacket(data []byte) []byte {
	osfs := &FilePacket{}
	prefix := data[:4]
	flagNum := data[4:6]

	fN := binary.BigEndian.Uint16(flagNum)
	var flags [][]byte
	index := 6
	for i := 0; i < int(fN); i++ {
		index = index + (i + 2)
		flags[i] = data[index : index+2]
		osfs.flags[i] = binary.BigEndian.Uint16(flags[i])
	}

	cBytes := make([]byte, 8)
	binary.PutUvarint(cBytes, uint64(PREFIX))

	index = index + 8

	if bytes.Compare(prefix, cBytes) != 0 {
		panic("invalid file format (not akf)")
	}

	osfs.prefix = binary.BigEndian.Uint32(prefix)

	sizeBytes := data[index : index+6] // we skip the 2 byte separator

	size := binary.BigEndian.Uint32(sizeBytes)

	osfs.size = size

	index = index + 4

	dataBytes := data[index : len(data)-2]
	if len(dataBytes) < int(size) {
		panic("data size mismatch")
	}

	osfs.data = dataBytes

	EOFb := data[len(data)-2:]

	EOF := binary.BigEndian.Uint16(EOFb)
	EOFc := uint16(0xafff)

	if EOF != EOFc {
		osfs = &FilePacket{} // we reset the packet as it is invalid
		panic("invalid end of file, file may be corrupted. stop reading.")
	}

	fBInt := big.NewInt(0).SetBytes(osfs.data)

	fBits := fBInt.Bits()
	osfs.bits = fBits

	return osfs.data

}

func (f *OSFSFile) setSize() {
	var buf *bytes.Buffer
	buf.Write(f.Data)
	f.Size = uint(buf.Len())
}
