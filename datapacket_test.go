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
}{
	{-1, 0, StateUnknown, "", "", "", []byte("foo"), []byte("foo"), []byte("bar"), []byte("bar"), 0, 0},
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
