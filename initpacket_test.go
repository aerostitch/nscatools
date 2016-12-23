package nscatools

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNewInitPacket(t *testing.T) {
	iv := []byte(strings.Repeat("a", 128))
	timenow := uint32(time.Now().Unix())
	pkt1, err := NewInitPacket(iv, timenow)
	if err != nil {
		t.Fatal(err)
	}
	pkt2, err := NewInitPacket(iv, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkt3, err := NewInitPacket(nil, timenow)
	if err != nil {
		t.Fatal(err)
	}
	pkt4, err := NewInitPacket(nil, 0)
	if err != nil || pkt4 == nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt1.Iv, iv) || !bytes.Equal(pkt2.Iv, iv) {
		t.Fatal("Wrong IV when providing a non-nil IV")
	}
	if pkt1.Timestamp != timenow || pkt3.Timestamp != timenow {
		t.Fatal("Wrong Timestamp when providing a non-nil timestamp")
	}
	if len(pkt3.Iv) != 128 || len(pkt4.Iv) != 128 {
		t.Fatal("Auto-generated initialization vector size incorrect")
	}
	// Assuming here than the tests take less than 20sec
	if pkt2.Timestamp < timenow || pkt2.Timestamp > timenow+20 {
		t.Fatal("Auto-generated timestamp not in the right time range")
	}
	if pkt4.Timestamp < timenow || pkt4.Timestamp > timenow+20 {
		t.Fatal("Auto-generated timestamp not in the right time range")
	}

}
