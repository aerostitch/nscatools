package nscatools

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

type pktCases []struct {
	versionOut      int16
	crcOut          uint32
	timestampIn     uint32
	stateIn         int16
	stateOut        int16
	hostNameIn      string
	hostNameOut     string
	serviceIn       string
	serviceOut      string
	pluginOutputIn  string
	pluginOutputOut string
	ivIn            *InitPacket
	ivOut           *InitPacket
	passwordIn      []byte
	passwordOut     []byte
	encryptionIn    int
	encryptionOut   int
	rawBuffer       []byte
	cryptBuffer     []byte
	networkPacket   *bytes.Buffer
}

// this builds the input networkPacket field based on the other fields of the
// test case but only for the xor and None encryptions
func buildNetworkPacket(packets *pktCases) {
	for _, pkt := range *packets {
		if pkt.encryptionIn != EncryptNone && pkt.encryptionIn != EncryptXOR {
			continue
		}
		buf := bytes.NewBuffer([]byte{})
		binary.Write(buf, binary.BigEndian, pkt.versionOut)
		buf.Write(make([]byte, 2))
		binary.Write(buf, binary.BigEndian, pkt.crcOut)
		binary.Write(buf, binary.BigEndian, pkt.timestampIn)
		binary.Write(buf, binary.BigEndian, pkt.stateOut)
		tmp := make([]byte, 64)
		copy(tmp, pkt.hostNameOut)
		buf.Write(tmp)
		tmp = make([]byte, 128)
		copy(tmp, pkt.serviceOut)
		buf.Write(tmp)
		tmp = make([]byte, 4096)
		copy(tmp, pkt.pluginOutputOut)
		buf.Write(tmp)
		buf.Write(make([]byte, 2))
		switch pkt.encryptionIn {
		case EncryptNone:
			pkt.networkPacket.Write(buf.Bytes())
		case EncryptXOR:
			buffer := buf.Bytes()
			bufferSize := len(buffer)
			ivSize := len(pkt.ivIn.Iv)
			pwdSize := len(pkt.passwordIn)
			// Rotating over the initialization vector of the connection
			for y := 0; y < bufferSize; y++ {
				// keep rotating over IV
				x := y % ivSize
				buffer[y] ^= pkt.ivIn.Iv[x]
			}
			// Then rotate again but this time on the password
			for y := 0; y < bufferSize; y++ {
				// keep rotating over password
				x := y % pwdSize
				buffer[y] ^= pkt.passwordIn[x]
			}
			pkt.networkPacket.Write(buffer)
		}

	}
}

// We need to reinitialize the values every time as we change the byte arrays
// during the testing process
func getPktCases() *pktCases {
	pkt := pktCases{
		{
			3, 0, uint32(time.Now().Unix()), StateCritical, StateCritical, "MyHost", "MyHost",
			"MyService", "MyService", "My output", "My output",
			&InitPacket{Iv: []byte("aerosmith"), Timestamp: uint32(time.Now().Unix())}, &InitPacket{Iv: []byte("aerosmith"), Timestamp: uint32(time.Now().Unix())},
			[]byte("freebird"), []byte("freebird"),
			EncryptNone, EncryptNone,
			[]byte("breaking the law"),
			[]byte("breaking the law"),
			bytes.NewBuffer([]byte{}),
		},
		{
			3, 0, uint32(time.Now().Unix()), StateOK, StateOK, "localhost", "localhost",
			"dummy service", "dummy service", "Everything is fine", "Everything is fine",
			&InitPacket{Iv: []byte("welcome to the jungle"), Timestamp: uint32(time.Now().Unix())}, &InitPacket{Iv: []byte("welcome to the jungle"), Timestamp: uint32(time.Now().Unix())},
			[]byte("crash"), []byte("crash"),
			EncryptXOR, EncryptXOR,
			[]byte("sympathy for the devil"),
			[]byte{0x67, 0x6e, 0x60, 0x60, 0x66, 0x7a, 0x7f, 0x38, 0x27, 0x61, 0x2c, 0x74, 0x29, 0x62, 0x20, 0x6c, 0x27, 0x6b, 0x71, 0x72, 0x6f, 0x69},
			bytes.NewBuffer([]byte{}),
		},
		{
			3, 0, uint32(time.Now().Unix()), StateUnknown, StateUnknown, "127.0.0.1", "127.0.0.1",
			"bla", "bla", "Dunno", "Dunno",
			&InitPacket{Iv: []byte("aerosmith"), Timestamp: uint32(time.Now().Unix())}, &InitPacket{Iv: []byte("aerosmith"), Timestamp: uint32(time.Now().Unix())},
			[]byte("freebird"), []byte("freebird"),
			EncryptRC6, EncryptRC6,
			[]byte("breaking the law"),
			[]byte("breaking the law"),
			bytes.NewBuffer(make([]byte, 4304)),
		},
	}
	buildNetworkPacket(&pkt)
	return &pkt
}

func TestNewDataPacket(t *testing.T) {
	cases := getPktCases()
	for _, tt := range *cases {
		pkt := NewDataPacket(tt.encryptionIn, tt.passwordIn, tt.ivIn)

		// Assuming it takes less than 5secs to generate a datapacket! :-D
		if pkt.Timestamp < tt.timestampIn || pkt.Timestamp > tt.timestampIn+5 {
			t.Error("Auto-generated timestamp not in the right time range")
		}

		if pkt.Version != 3 {
			t.Errorf("Expecting version: %d, got: %d\n", 3, pkt.Version)
		}
		if pkt.Crc != tt.crcOut {
			t.Errorf("Expecting crc: %d, got: %d\n", tt.crcOut, pkt.Crc)
		}
		if pkt.State != 3 {
			t.Errorf("Expecting state: %d, got: %d\n", 3, pkt.State)
		}
		if pkt.HostName != "" {
			t.Errorf("Expecting hostname: %s, got: %s\n", "", pkt.HostName)
		}
		if pkt.Service != "" {
			t.Errorf("Expecting service: %s, got: %s\n", "", pkt.Service)
		}
		if pkt.PluginOutput != "" {
			t.Errorf("Expecting plugin output: %s, got: %s\n", "", pkt.PluginOutput)
		}
		if !bytes.Equal(pkt.Ipkt.Iv, tt.ivOut.Iv) {
			t.Errorf("Expecting Iv: %s, got: %s\n", tt.ivOut.Iv, pkt.Ipkt.Iv)
		}
		if !bytes.Equal(pkt.Password, tt.passwordOut) {
			t.Errorf("Expecting password: %d, got: %d\n", tt.passwordOut, pkt.Password)
		}
		if pkt.Encryption != tt.encryptionOut {
			t.Errorf("Expecting encryption: %d, got: %d\n", tt.encryptionOut, pkt.Encryption)
		}
	}
}

func TestDataPacketXor(t *testing.T) {
	cases := getPktCases()
	for _, tt := range *cases {
		pkt := NewDataPacket(tt.encryptionIn, tt.passwordIn, tt.ivIn)
		pkt.xor(tt.rawBuffer)
		// When not a xor encryption, the cryptBuffer is not encrypted so we revert
		// by doing a 2nd xor, checking the reversability at the same time
		if pkt.Encryption != 1 {
			pkt.xor(tt.rawBuffer)
		}
		if !bytes.Equal(tt.rawBuffer, tt.cryptBuffer) {
			t.Errorf("Expecting buffer: %s, got: %s\n", tt.cryptBuffer, tt.rawBuffer)
		}
	}
}

// Checks the error from the Encrypt/Decrypt function
func checkEncryptDecryptError(t *testing.T, pkt *DataPacket, err error) {
	if pkt.Encryption == EncryptRC6 || pkt.Encryption == EncryptMARS || pkt.Encryption == EncryptPANAMA || pkt.Encryption == EncryptIDEA {
		if err.Error() != "Unimplemented encryption algorithm" {
			t.Errorf("pkt.Encrypt returned: %s\n", err)
		} else {
			t.Logf("Note: RC6, MARS, PANAMA and IDEA were not implemented in the NSCA original server")
		}
	} else {
		t.Errorf("Packet encyption/decryption returned: %s\n", err)
	}
}

func TestDataPacketDecrypt(t *testing.T) {
	cases := getPktCases()
	for _, tt := range *cases {
		pkt := NewDataPacket(tt.encryptionIn, tt.passwordIn, tt.ivIn)
		if err := pkt.Decrypt(tt.cryptBuffer); err != nil {
			checkEncryptDecryptError(t, pkt, err)
		}
		if !bytes.Equal(tt.cryptBuffer, tt.rawBuffer) {
			t.Errorf("Expecting buffer: %s, got: %s\n", tt.rawBuffer, tt.cryptBuffer)
		}
	}
}

// Same as Encrypt but buffer in and out reverted
func TestDataPacketEncrypt(t *testing.T) {
	cases := getPktCases()
	for _, tt := range *cases {
		pkt := NewDataPacket(tt.encryptionIn, tt.passwordIn, tt.ivIn)
		if err := pkt.Encrypt(tt.rawBuffer); err != nil {
			checkEncryptDecryptError(t, pkt, err)
		}
		if !bytes.Equal(tt.rawBuffer, tt.cryptBuffer) {
			t.Errorf("Expecting buffer: %s, got: %s\n", tt.cryptBuffer, tt.rawBuffer)
		}
	}
}

func TestDataPacketRead(t *testing.T) {
	cases := getPktCases()
	for _, tt := range *cases {
		pkt := NewDataPacket(tt.encryptionIn, tt.passwordIn, tt.ivIn)
		if err := pkt.Read(tt.networkPacket); err != nil {
			checkEncryptDecryptError(t, pkt, err)
		}

		// We're only testing the Read transformation input -> attributes with Xor
		// and None as encryptions. The rest of the encryption processes are tested
		// directly in the tests for Encrypt and Decrypt methods
		if tt.encryptionIn != EncryptNone && tt.encryptionIn != EncryptXOR {
			t.Logf("Note: For the test of the Read method, only encryptions None and Xor output are tested")
			continue
		}

		if pkt.Version != tt.versionOut {
			t.Errorf("Expecting version: %d, got: %d\n", tt.versionOut, pkt.Version)
		}
		if pkt.Crc != tt.crcOut {
			t.Errorf("Expecting CRC: %d, got: %d\n", tt.crcOut, pkt.Crc)
		}
		if pkt.Timestamp != tt.timestampIn {
			t.Errorf("Expecting timestamp: %d, got: %d\n", tt.timestampIn, pkt.Timestamp)
		}
		if pkt.State != tt.stateOut {
			t.Errorf("Expecting state: %d, got: %d\n", tt.stateOut, pkt.State)
		}
		if pkt.HostName != tt.hostNameOut {
			t.Errorf("Expecting hostname: %s, got: %s\n", tt.hostNameOut, pkt.HostName)
		}
		if pkt.Service != tt.serviceOut {
			t.Errorf("Expecting state: %s, got: %s\n", tt.serviceOut, pkt.Service)
		}
		if pkt.PluginOutput != tt.pluginOutputOut {
			t.Errorf("Expecting plugin output: %s, got: %s\n", tt.pluginOutputOut, pkt.PluginOutput)
		}
	}
}

// Receiving a datapacket with the wrong size
func TestDataPacketReadWrongSize(t *testing.T) {
	pkt := NewDataPacket(0, []byte{0x00}, &InitPacket{})
	if err := pkt.Read(bytes.NewBuffer(make([]byte, 10))); err != nil {
		if err.Error() != "unexpected EOF" {
			checkEncryptDecryptError(t, pkt, err)
		}
	}
}

func TestDataPacketWrite(t *testing.T) {
	cases := getPktCases()
	for _, tt := range *cases {
		b := new(bytes.Buffer)
		pkt := NewDataPacket(tt.encryptionIn, tt.passwordIn, tt.ivIn)
		pkt.Timestamp = tt.timestampIn
		pkt.State = tt.stateIn
		pkt.HostName = tt.hostNameIn
		pkt.Service = tt.serviceIn
		pkt.PluginOutput = tt.pluginOutputIn

		if err := pkt.Write(b); err != nil {
			checkEncryptDecryptError(t, pkt, err)
		}
		// We're only testing the Write method with Xor
		// and None as encryptions. The rest of the encryption processes are tested
		// directly in the tests for Encrypt and Decrypt methods
		if tt.encryptionIn != EncryptNone && tt.encryptionIn != EncryptXOR {
			t.Logf("Note: For the test of the Read method, only encryptions None and Xor output are tested")
			continue
		}

		if !bytes.Equal(b.Bytes(), tt.networkPacket.Bytes()) {
			t.Errorf("expecting : %v, got: %v", tt.networkPacket.Bytes(), b.Bytes())
		}
	}
}

// Reusing the writerMock created in initpacket_test.go
func TestDataPacketWriteInconsistentResult(t *testing.T) {
	m := writerMock{}
	pkt := NewDataPacket(0, []byte{}, &InitPacket{})
	if err := pkt.Write(&m); err.Error() != "0 bytes written, expecting 4304. Error: %!s(<nil>)" {
		t.Errorf("DataPacket.Write() should signal inconsistent number of bytes but outputed: %s", err)
	}
}
