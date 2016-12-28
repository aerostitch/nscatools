package nscatools

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestNewInitPacket(t *testing.T) {
	timenow := uint32(time.Now().Unix())
	pkt, err := NewInitPacket()
	if err != nil || pkt == nil {
		t.Error(err)
	}

	if len(pkt.Iv) != 128 {
		t.Error("Auto-generated initialization vector size incorrect")
	}
	// Assuming here than the tests take less than 5sec
	if pkt.Timestamp < timenow || pkt.Timestamp > timenow+5 {
		t.Error("Auto-generated timestamp not in the right time range")
	}

}

func TestInitPacketWrite(t *testing.T) {
	var b bytes.Buffer
	iv := []byte(strings.Repeat("a", 128))
	ivOut := make([]byte, 128)
	timenow := uint32(time.Now().Unix())
	var timeOut uint32

	pkt := InitPacket{Iv: iv, Timestamp: timenow}
	if err := pkt.Write(&b); err != nil {
		t.Errorf("pkt.Write() errored: %s", err)
	}

	// Parse results
	if err := binary.Read(&b, binary.BigEndian, ivOut); err != nil {
		t.Errorf("binary.Read failed for iv:%s\n", err)
	}
	if err := binary.Read(&b, binary.BigEndian, &timeOut); err != nil {
		t.Errorf("binary.Read failed for the timestamp: %s\n", err)
	}

	// Check results
	if !bytes.Equal(iv, ivOut) {
		t.Errorf("Expecting iv to be: %v\nGot: %v", iv, ivOut)
	}
	if timenow != timeOut {
		t.Errorf("Expecting iv to be: %d\nGot: %d", timenow, timeOut)
	}
}

// This part is used for testing a number of bytes written not corresponding to
// the expected packet size.
// Note: this is also used in datapacket_test.go
type writerMock struct{}

func (m *writerMock) Write(p []byte) (int, error) {
	return 0, nil
}
func TestInitPacketWriteInconsistentResult(t *testing.T) {
	m := writerMock{}
	pkt, err := NewInitPacket()
	if err != nil {
		t.Errorf("NewInitPacket() errored: %s", err)
	}
	if err = pkt.Write(&m); err.Error() != "0 bytes written but the packet is 132 bytes" {
		t.Errorf("InitPacket.Write() should signal inconsistent number of bytes but outputed: %s", err)
	}
}

func TestInitPacketRead(t *testing.T) {
	iv := []byte(strings.Repeat("a", 128))
	ivOut := []byte(strings.Repeat("a", 128))
	timenow := uint32(time.Now().Unix())
	timeOut := timenow
	buf := bytes.NewBuffer(iv)
	binary.Write(buf, binary.BigEndian, &timenow)

	ipkt := InitPacket{}
	if err := ipkt.Read(buf); err != nil {
		t.Errorf("InitPacket.Read returned: %s\n", err)
	}

	// Check results
	if !bytes.Equal(ipkt.Iv, ivOut) {
		t.Errorf("Expecting iv to be: %s\nGot: %s", ivOut, ipkt.Iv)
	}
	if ipkt.Timestamp != timeOut {
		t.Errorf("Expecting timestamp to be: %d\nGot: %d", timeOut, ipkt.Timestamp)
	}
}

func TestInitPacketReadWrongSize(t *testing.T) {
	buf := bytes.NewBuffer(make([]byte, 10))
	ipkt := InitPacket{}
	if err := ipkt.Read(buf); err == nil || err.Error() != "expecting to receive 132 bytes. Got 10 and error: %!s(<nil>)" {
		t.Errorf("InitPacket.Read check for input packet size broken: %s\n", err)
	}
}
