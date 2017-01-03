// Package nscatools is a flexible library that allows you to easily create a
// custom NSCA (Nagios Service Check Acceptor) client and server in pure Go.
// Note: the package requires libmcrypt to work for now (under Debian-based
// systems, the packages are named libmcrypt4 and libmcrypt-dev)
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

// NewInitPacket initialize an InitPacket by creating a random initialization
// vector and filling the timestamp attribute with the current epoch time
func NewInitPacket() (*InitPacket, error) {
	initp := InitPacket{Iv: make([]byte, 128), Timestamp: 0}
	var err error
	_, err = rand.Read(initp.Iv)
	initp.Timestamp = uint32(time.Now().Unix())
	return &initp, err
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

// Read fetches the init packet from an io.Reader such as a TCPConnection and
// fills the current InitPacket instance attributes with it
func (p *InitPacket) Read(r io.Reader) error {
	packet := make([]byte, 132)
	if n, err := r.Read(packet); err != nil || n != 132 {
		return fmt.Errorf("expecting to receive 132 bytes. Got %d and error: %s", n, err)
	}

	p.Iv = make([]byte, 128)
	copy(p.Iv, packet[0:128])
	p.Timestamp = binary.BigEndian.Uint32(packet[128:])
	return nil
}
