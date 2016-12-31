package nscatools

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"log"
	"net"
	"testing"
	"time"
)

// Helper to create a client and send data
func sendClientMessage(t *testing.T) {
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.BigEndian, int16(3))
	buf.Write(make([]byte, 6))
	binary.Write(buf, binary.BigEndian, uint32(time.Now().Unix()))
	binary.Write(buf, binary.BigEndian, int16(StateOK))
	tmp := make([]byte, 64)
	copy(tmp, "remote host")
	buf.Write(tmp)
	tmp = make([]byte, 128)
	copy(tmp, "application liveness")
	buf.Write(tmp)
	tmp = make([]byte, 4096)
	copy(tmp, "I am alive!")
	buf.Write(tmp)
	buf.Write(make([]byte, 2))

	b := buf.Bytes()
	crcdPacket := make([]byte, 4304)
	copy(crcdPacket, b[0:4])
	copy(crcdPacket[8:], b[8:])
	crc := crc32.ChecksumIEEE(crcdPacket)
	binary.BigEndian.PutUint32(b[4:8], crc)

	conn, err := net.DialTimeout("tcp", "localhost:5667", time.Second)
	if err != nil {
		t.Errorf("unable to connect to the provided port: %s\n", err)
	}
	defer conn.Close()

	if _, err = conn.Read(make([]byte, 132)); err != nil {
		t.Errorf("unable to read from the connection: %s\n", err)
	}

	if _, err = conn.Write(b); err != nil {
		t.Errorf("unable to write to the connection: %s\n", err)
	}
}

// returnDataAsError is a helper that returns the informations as a string based
// on what has been received
func returnDataAsError(p *DataPacket) error {
	return fmt.Errorf("%d\n%d\n%s\n%s\n%s", p.Version, p.State, p.HostName, p.Service, p.PluginOutput)
}

func TestStartServer(t *testing.T) {
	// t.Fatalf("Not implemented...\n")
}

// TestHandleClient tests that we can read and write data from a given socket
// with the HandleClient function by simulating a connection attempt
func TestHandleClient(t *testing.T) {

	// Connection attempt
	go sendClientMessage(t)

	// Listener to embed the HandleClient in.
	tcpAddr, err := net.ResolveTCPAddr("tcp", "localhost:5667")
	if err != nil {
		t.Errorf("Unable to resolve address: %s\n", err)
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		t.Errorf("unable to bind the port: %s\n", err)
	}
	defer listener.Close()

	// Testing only 1 connection handling here so no for loop needed
	conn, err := listener.Accept()
	if err != nil {
		t.Errorf("unable to open the listener %s\n", err)
		return
	}
	defer conn.Close()

	expectedError := "3\n0\nremote host\napplication liveness\nI am alive!"
	cfg := NewConfig("localhost", 5667, EncryptNone, "", returnDataAsError)
	err = HandleClient(cfg, conn, log.New(ioutil.Discard, "", 0))
	if err.Error() != expectedError {
		t.Errorf("unexpected return value. Got: %s, expecting %s\n", err, expectedError)
	}
	return
}
