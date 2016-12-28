package nscatools

import (
	"io/ioutil"
	"log"
	"net"
	"testing"
)

// To avoid rewriting everything, we use the HandleClient function to manage the
// server part.
func TestSendStatus(t *testing.T) {
	go func() {
		cfg := NewConfig("", 5667, EncryptNone, "", nil)
		err := SendStatus(cfg, "myHost", "my service", StateWarning, "You'd better fix me before I go critical")
		if err != nil {
			t.Errorf("SendStatus returned an error: %s\n", err)
		}
	}()

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

	// Testing only 1 connection handling here
	// so no for loop needed
	conn, err := listener.Accept()
	if err != nil {
		t.Errorf("unable to open the listener %s\n", err)
		return
	}
	defer conn.Close()

	expectedError := "3\n1\nmyHost\nmy service\nYou'd better fix me before I go critical"
	cfg := NewConfig("", 5667, EncryptNone, "", returnDataAsError)
	err = HandleClient(cfg, conn, log.New(ioutil.Discard, "", 0))
	if err.Error() != expectedError {
		t.Errorf("unexpected return value. Got: %s, expecting %s\n", err, expectedError)
	}
	return
}

// This one is expected to timeout as no server is listening
func TestSendStatusTimeout(t *testing.T) {
	cfg := NewConfig("", 5667, EncryptNone, "", nil)
	err := SendStatus(cfg, "myHost", "my service", StateWarning, "You'd better fix me before I go critical")
	if err == nil || err.Error() != "unable to connect to the provided server: dial tcp [::1]:5667: getsockopt: connection refused" {
		t.Errorf("SendStatus returned an unexpected error when no server listening: %s\n", err)
	}
}
