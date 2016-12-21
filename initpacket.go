package nscatools

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// InitPacket is used during the handshake with the client
type InitPacket struct {
	// initialization vector is a 128 bytes array
	Iv        []byte
	Timestamp uint32
}

// NewInitPacket initialize an InitPacket with the expected values based on the password,
// encyrption and potentially received initialization vector
func NewInitPacket(password string, encryption int, receivedIv []byte) (*InitPacket, error) {
	initp := InitPacket{Iv: make([]byte, 128), Timestamp: 0}
	if receivedIv == nil {
		if _, err := rand.Read(initp.Iv); err != nil {
			return &initp, err
		}
	}
	initp.Timestamp = uint32(time.Now().Unix())
	return &initp, nil
}

// Write writes the current InitPacket to an io.Writer such as a TCPConnection
func (p *InitPacket) Write(w io.Writer) error {
	// Transforming to network bytes
	packet := new(bytes.Buffer)
	binary.Write(packet, binary.BigEndian, p.Iv)
	binary.Write(packet, binary.BigEndian, p.Timestamp)
	b := packet.Bytes()
	n, err := w.Write(b)
	// Consistency check
	if err == nil && n != len(b) {
		err = fmt.Errorf("%d bytes written but the packet is %d bytes", n, len(b))
	}
	return err
}
