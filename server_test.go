package nscatools

import (
	//"fmt"
	//"net"
	"testing"
)

/*
TODO:
 * redo TestHandleClient
 * Service Checks: <host_name>[tab]<svc_description>[tab]<return_code>[tab]<plugin_output>[newline]
 * Host Checks: <host_name>[tab]<return_code>[tab]<plugin_output>[newline]
*/

// TestHandleClient tests that we can read and write data from a given socket
// with the HandleClient function by simulating a connection attempt.
func TestHandleClient(t *testing.T) {
	//message := "localhost myService 1 myOutput\n"

	//// Connection attempt
	//go func() {
	//	conn, err := net.Dial("tcp", ":5667")
	//	if err != nil {
	//		t.Fatal(err)
	//	}
	//	defer conn.Close()

	//	if _, err := fmt.Fprintf(conn, message); err != nil {
	//		t.Fatal(err)
	//	}
	//}()

	//// Listener to embed the HandleClient in.
	//listener, err := net.Listen("tcp", ":5667")
	//if err != nil {
	//	t.Fatal(err)
	//}
	//defer listener.Close()

	//for {
	//	conn, err := listener.Accept()
	//	if err != nil {
	//		return
	//	}
	//	defer conn.Close()

	//	cfg := NewConfig("", 5667, 0, "")
	//	buf, err := HandleClient(cfg, conn)
	//	if err != nil {
	//		t.Fatal(err)
	//	}

	//	data := DataPacket{}
	//	if msg := string(buf[:]); msg != message {
	//		t.Logf("Buffer size: %v\n", len(buf))
	//		t.Fatalf("Unexpected message:\nGot:\t\t-%s-\nExpected:\t-%s-\n", msg, message)
	//	}
	//	return // Done
	//}

}

func TestStartServer(t *testing.T) {
	// t.Fatalf("Not implemented...\n")
}
