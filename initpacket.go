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

// NewInitPacket initialize an InitPacket with the given initialization vector
// and Timestamp. If you don't have a timestamp or IV and want them to be
// generated, just pass nil to receivedIv and 0 to receivedTimestamp
func NewInitPacket(receivedIv []byte, receivedTimestamp uint32) (*InitPacket, error) {
	initp := InitPacket{Iv: make([]byte, 128), Timestamp: 0}
	if receivedIv == nil {
		if _, err := rand.Read(initp.Iv); err != nil {
			return &initp, err
		}
	} else {
		initp.Iv = receivedIv
	}
	if receivedTimestamp == 0 {
		initp.Timestamp = uint32(time.Now().Unix())
	} else {
		initp.Timestamp = receivedTimestamp
	}
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
