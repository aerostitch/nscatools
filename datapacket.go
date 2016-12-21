package nscatools

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// DataPacket stores the data received for the client-server communication
type DataPacket struct {
	Version      int16
	Crc          uint32
	Timestamp    uint32
	State        int16
	HostName     string
	Service      string
	PluginOutput string
	Iv           []byte
	Password     []byte
	Encryption   int
}

// NewDataPacket initializes a new blank data packet
func NewDataPacket(encryption int, password, iv []byte) *DataPacket {
	packet := DataPacket{
		Version:      -1,
		Crc:          0,
		Timestamp:    uint32(time.Now().Unix()),
		State:        StateUnknown,
		HostName:     "",
		Service:      "",
		PluginOutput: "",
		Iv:           iv,
		Password:     password,
		Encryption:   encryption,
	}
	return &packet
}

// Read gets the data packet and populates the attributes of the DataPacket
// according. When encountering an error, it returns the error and don't process
// further.
//
// TODO:
//   * Add the check of the crc32 value?
//   * Add the packet max age check
func (p *DataPacket) Read(conn io.Reader) error {
	// We need to read the full packet 1st to check the crc and decrypt it too
	pos := 0
	fullPacket := make([]byte, 4304)
	if _, err := io.ReadFull(conn, fullPacket); err != nil {
		return err
	}

	if err := p.Decrypt(fullPacket); err != nil {
		return err
	}

	// Split the data of the full packet in the different fields
	sep := []byte("\x00") // sep is used to extract only the useful string
	int16Bytes := make([]byte, 2)
	uint32Bytes := make([]byte, 4)

	copy(int16Bytes, fullPacket[pos:])
	pos += 2
	p.Version = int16(binary.BigEndian.Uint16(int16Bytes))
	// We don't care about those next 2 bytes
	copy(int16Bytes, fullPacket[pos:])
	pos += 2
	copy(uint32Bytes, fullPacket[pos:])
	pos += 4
	p.Crc = binary.BigEndian.Uint32(uint32Bytes)
	copy(uint32Bytes, fullPacket[pos:])
	pos += 4
	p.Timestamp = binary.BigEndian.Uint32(uint32Bytes)
	copy(int16Bytes, fullPacket[pos:])
	pos += 2
	p.State = int16(binary.BigEndian.Uint16(int16Bytes))
	host := make([]byte, 64)

	copy(host, fullPacket[pos:])
	pos += 64
	p.HostName = string(bytes.Split(host, sep)[0])

	svc := make([]byte, 128)
	copy(svc, fullPacket[pos:])
	pos += 128
	p.Service = string(bytes.Split(svc, sep)[0])

	output := make([]byte, 4096)
	copy(output, fullPacket[pos:])
	p.PluginOutput = string(bytes.Split(output, sep)[0])
	// We discard the last 2 bytes

	return nil
}

// Performs a XOR operation on a buffer using the initialization vector and the
// password.
func (p *DataPacket) xor(buffer []byte) {
	bufferSize := len(buffer)
	ivSize := len(p.Iv)
	pwdSize := len(p.Password)
	// Rotating over the initialization vector of the connection
	for y := 0; y < bufferSize; y++ {
		// keep rotating over IV
		x := y % ivSize
		buffer[y] ^= p.Iv[x]
	}

	// Then rotate again but this time on the password
	for y := 0; y < bufferSize; y++ {
		// keep rotating over password
		x := y % pwdSize
		buffer[y] ^= p.Password[x]
	}
}

// Decrypt decrypts a buffer
func (p *DataPacket) Decrypt(buffer []byte) error {
	switch p.Encryption {
	case EncryptNone: // Just don't do anything
	case EncryptXOR:
		p.xor(buffer)
	case EncryptDES:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case Encrypt3DES:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptCAST128:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptCAST256:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptXTEA:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case Encrypt3WAY:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptBLOWFISH:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptTWOFISH:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptLOKI97:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptRC2:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptARCFOUR:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptRC6: // Unsupported in standard NSCA
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptRIJNDAEL128:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptRIJNDAEL192:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptRIJNDAEL256:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptMARS: // Unsupported in standard NSCA
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptPANAMA: // Unsupported in standard NSCA
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptWAKE:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptSERPENT:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptIDEA: // Unsupported in standard NSCA
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptENIGMA:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptGOST:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptSAFER64:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptSAFER128:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptSAFERPLUS:
		return fmt.Errorf("Unimplemented encryption algorithm")
	default:
		return fmt.Errorf("%d is an unrecognized encryption integer", p.Encryption)
	}
	return nil
}

// Encrypt encrypts a buffer
func (p *DataPacket) Encrypt(buffer []byte) error {
	switch p.Encryption {
	case EncryptNone:
	case EncryptXOR:
		p.xor(buffer)
	case EncryptDES:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case Encrypt3DES:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptCAST128:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptCAST256:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptXTEA:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case Encrypt3WAY:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptBLOWFISH:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptTWOFISH:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptLOKI97:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptRC2:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptARCFOUR:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptRC6: // Unsupported in standard NSCA
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptRIJNDAEL128:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptRIJNDAEL192:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptRIJNDAEL256:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptMARS: // Unsupported in standard NSCA
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptPANAMA: // Unsupported in standard NSCA
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptWAKE:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptSERPENT:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptIDEA: // Unsupported in standard NSCA
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptENIGMA:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptGOST:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptSAFER64:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptSAFER128:
		return fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptSAFERPLUS:
		return fmt.Errorf("Unimplemented encryption algorithm")
	default:
		return fmt.Errorf("%d is an unrecognized encryption integer", p.Encryption)
	}
	return nil
}

// Write generates the buffer to write to the writer based on the populated
// fields of the DataPacket instance encrypts it if needed and send it to the
// writer.
// When encountering an error, it returns the error and don't process
// further.
func (p *DataPacket) Write(conn io.Writer) error {
	return nil
}

// Encrypt* are the encryptions supported by the standard NSCA configuration
const (
	EncryptNone        = iota // no encryption
	EncryptXOR                // Simple XOR  (No security, just obfuscation, but very fast)
	EncryptDES                // DES
	Encrypt3DES               // 3DES or Triple DES
	EncryptCAST128            // CAST-128
	EncryptCAST256            // CAST-256
	EncryptXTEA               // xTEA
	Encrypt3WAY               // 3-WAY
	EncryptBLOWFISH           // SKIPJACK
	EncryptTWOFISH            // TWOFISH
	EncryptLOKI97             // LOKI97
	EncryptRC2                // RC2
	EncryptARCFOUR            // RC4
	EncryptRC6                // RC6 - Unsupported in standard NSCA
	EncryptRIJNDAEL128        // AES-128
	EncryptRIJNDAEL192        // AES-192
	EncryptRIJNDAEL256        // AES-256
	EncryptMARS               // MARS - Unsupported in standard NSCA
	EncryptPANAMA             // PANAMA - Unsupported in standard NSCA
	EncryptWAKE               // WAKE
	EncryptSERPENT            // SERPENT
	EncryptIDEA               // IDEA - Unsupported in standard NSCA
	EncryptENIGMA             // ENIGMA (Unix crypt)
	EncryptGOST               // GOST
	EncryptSAFER64            // SAFER-sk64
	EncryptSAFER128           // SAFER-sk128
	EncryptSAFERPLUS          // SAFER+
)

// State* are the states understood by NSCA
const (
	StateOK = iota
	StateWarning
	StateCritical
	StateUnknown
)
