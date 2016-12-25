package nscatools

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestNewInitPacket(t *testing.T) {
	iv := []byte(strings.Repeat("a", 128))
	timenow := uint32(time.Now().Unix())
	pkt1, err := NewInitPacket(iv, timenow)
	if err != nil {
		t.Error(err)
	}
	pkt2, err := NewInitPacket(iv, 0)
	if err != nil {
		t.Error(err)
	}
	pkt3, err := NewInitPacket(nil, timenow)
	if err != nil {
		t.Error(err)
	}
	pkt4, err := NewInitPacket(nil, 0)
	if err != nil || pkt4 == nil {
		t.Error(err)
	}

	if !bytes.Equal(pkt1.Iv, iv) || !bytes.Equal(pkt2.Iv, iv) {
		t.Error("Wrong IV when providing a non-nil IV")
	}
	if pkt1.Timestamp != timenow || pkt3.Timestamp != timenow {
		t.Error("Wrong Timestamp when providing a non-nil timestamp")
	}
	if len(pkt3.Iv) != 128 || len(pkt4.Iv) != 128 {
		t.Error("Auto-generated initialization vector size incorrect")
	}
	// Assuming here than the tests take less than 5sec
	if pkt2.Timestamp < timenow || pkt2.Timestamp > timenow+5 {
		t.Error("Auto-generated timestamp not in the right time range")
	}
	if pkt4.Timestamp < timenow || pkt4.Timestamp > timenow+20 {
		t.Error("Auto-generated timestamp not in the right time range")
	}

}

func TestInitPacketWrite(t *testing.T) {
	var b bytes.Buffer
	iv := []byte(strings.Repeat("a", 128))
	ivOut := make([]byte, 128)
	timenow := uint32(time.Now().Unix())
	var timeOut uint32

	pkt, err := NewInitPacket(iv, timenow)
	if err != nil {
		t.Errorf("NewInitPacket() errored: %s", err)
	}
	if err = pkt.Write(&b); err != nil {
		t.Errorf("pkt.Write() errored: %s", err)
	}

	// Parse results
	if err = binary.Read(&b, binary.BigEndian, ivOut); err != nil {
		t.Errorf("binary.Read failed for iv:%s\n", err)
	}
	if err = binary.Read(&b, binary.BigEndian, &timeOut); err != nil {
		t.Errorf("binary.Read failed for the timestamp: %s\n", err)
	}

	// Check results
	if !bytes.Equal(iv, ivOut) {
		t.Errorf("Expecting iv to be: %s\nGot: %s", iv, ivOut)
	}
	if timenow != timeOut {
		t.Errorf("Expecting iv to be: %s\nGot: %s", iv, ivOut)
	}
}

// This part is used for testing a number of bytes written not corresponding to
// the expected packet size.
type writerMock struct{}

func (m *writerMock) Write(p []byte) (int, error) {
	return 0, nil
}
func TestWriteInconsistentResult(t *testing.T) {
	m := writerMock{}
	iv := []byte(strings.Repeat("a", 128))
	timenow := uint32(time.Now().Unix())
	pkt, err := NewInitPacket(iv, timenow)
	if err != nil {
		t.Errorf("NewInitPacket() errored: %s", err)
	}
	if err = pkt.Write(&m); err.Error() != "0 bytes written but the packet is 132 bytes" {
		t.Errorf("pkt.Write() should signal inconsistent number of bytes but outputed: %s", err)
	}
}
