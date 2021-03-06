package nscatools

import (
	"fmt"
	"testing"
)

var testcases = []struct {
	hostIn        string
	hostOut       string
	portIn        uint16
	portOut       uint16
	encryptionIn  int
	encryptionOut int
	passwordIn    string
	passwordOut   string
}{
	{"myHost", "myHost", 5668, 5668, 0, 0, "", ""},
	{"", "localhost", 0, 5667, 3, 3, "Blablabla", "Blablabla"},
}

func testDataHandler(dp *DataPacket) error {
	return fmt.Errorf("all good")
}

func TestNewConfig(t *testing.T) {
	for _, tt := range testcases {
		conf := NewConfig(tt.hostIn, tt.portIn, tt.encryptionIn, tt.passwordIn, testDataHandler)
		switch {
		case conf.Host != tt.hostOut:
			t.Errorf("Unexpected hostname: %s. Expected: %s", conf.Host, tt.hostOut)
		case conf.Port != tt.portOut:
			t.Errorf("Unexpected port: %d. Expected: %d", conf.Port, tt.portOut)
		case conf.EncryptionMethod != tt.encryptionOut:
			t.Errorf("Unexpected encryption: %d. Expected: %d", conf.EncryptionMethod, tt.encryptionOut)
		case conf.Password != tt.passwordOut:
			t.Errorf("Unexpected encryption: %s. Expected: %s", conf.Password, tt.passwordOut)
		case conf.MaxHostnameSize != 64:
			t.Errorf("Unexpected max hostname size: %d. Expected: %d", conf.MaxHostnameSize, 64)
		case conf.MaxDescriptionSize != 128:
			t.Errorf("Unexpected max description size: %d. Expected: %d", conf.MaxDescriptionSize, 128)
		case conf.MaxPluginOutputSize != 4096:
			t.Errorf("Unexpected plugin output size: %d. Expected: %d", conf.MaxPluginOutputSize, 4096)
		}
		if f := conf.PacketHandler(&DataPacket{}); f.Error() != "all good" {
			t.Errorf("Handler is not returning the expected value: %s", f)
		}
	}

}
