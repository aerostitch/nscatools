package nscatools

import (
	"bytes"
	"testing"
	"time"
)

var newPktCases = []struct {
	versionOut      int16
	crcOut          uint32
	stateOut        int16
	hostNameOut     string
	serviceOut      string
	pluginOutputOut string
	ivIn            []byte
	ivOut           []byte
	passwordIn      []byte
	passwordOut     []byte
	encryptionIn    int
	encryptionOut   int
	bufferIn        []byte
	bufferOut       []byte
}{
	{-1, 0, StateUnknown, "", "", "", []byte("aerosmith"), []byte("aerosmith"), []byte("freebird"), []byte("freebird"), 0, 0, []byte("breaking the law"), []byte("breaking the law")},
	{-1, 0, StateUnknown, "", "", "", []byte("welcome to the jungle"), []byte("welcome to the jungle"), []byte("crash"), []byte("crash"), 1, 1, []byte("sympathy for the devil"), []byte{0x67, 0x6e, 0x60, 0x60, 0x66, 0x7a, 0x7f, 0x38, 0x27, 0x61, 0x2c, 0x74, 0x29, 0x62, 0x20, 0x6c, 0x27, 0x6b, 0x71, 0x72, 0x6f, 0x69}},
}

func TestNewDataPacket(t *testing.T) {
	for _, tt := range newPktCases {
		ts := uint32(time.Now().Unix())
		pkt := NewDataPacket(tt.encryptionIn, tt.passwordIn, tt.ivIn)

		// Assuming it takes less than 5secs to generate a datapacket! :-D
		if pkt.Timestamp < ts || pkt.Timestamp > ts+5 {
			t.Error("Auto-generated timestamp not in the right time range")
		}

		if pkt.Version != tt.versionOut {
			t.Errorf("Expecting version: %d, got: %d\n", tt.versionOut, pkt.Version)
		}
		if pkt.Crc != tt.crcOut {
			t.Errorf("Expecting crc: %d, got: %d\n", tt.crcOut, pkt.Crc)
		}
		if pkt.State != tt.stateOut {
			t.Errorf("Expecting state: %d, got: %d\n", tt.stateOut, pkt.State)
		}
		if pkt.HostName != tt.hostNameOut {
			t.Errorf("Expecting hostname: %s, got: %s\n", tt.hostNameOut, pkt.HostName)
		}
		if pkt.Service != tt.serviceOut {
			t.Errorf("Expecting service: %s, got: %s\n", tt.serviceOut, pkt.Service)
		}
		if pkt.PluginOutput != tt.pluginOutputOut {
			t.Errorf("Expecting plugin output: %s, got: %s\n", tt.pluginOutputOut, pkt.PluginOutput)
		}
		if !bytes.Equal(pkt.Iv, tt.ivOut) {
			t.Errorf("Expecting Iv: %s, got: %s\n", tt.ivOut, pkt.Iv)
		}
		if !bytes.Equal(pkt.Password, tt.passwordOut) {
			t.Errorf("Expecting password: %d, got: %d\n", tt.passwordOut, pkt.Password)
		}
		if pkt.Encryption != tt.encryptionOut {
			t.Errorf("Expecting encryption: %d, got: %d\n", tt.encryptionOut, pkt.Encryption)
		}
	}
}

func TestXor(t *testing.T) {
	for _, tt := range newPktCases {
		pkt := NewDataPacket(tt.encryptionIn, tt.passwordIn, tt.ivIn)
		pkt.xor(tt.bufferIn)
		// When not a xor encryption, the bufferOut is not encrypted so we revert
		// by doing a 2nd xor, checking the reversability at the same time
		if pkt.Encryption != 1 {
			pkt.xor(tt.bufferIn)
		}
		if !bytes.Equal(tt.bufferIn, tt.bufferOut) {
			t.Errorf("Expecting buffer: %s, got: %s\n", tt.bufferOut, tt.bufferIn)
		}
	}
}
