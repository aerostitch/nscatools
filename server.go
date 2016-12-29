package nscatools

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
)

// StartServer starts an NSCA server
func StartServer(conf *Config, debug bool) {
	// Initializing logging objects
	var dbg, logErr *log.Logger
	debugHandle := ioutil.Discard
	if debug {
		debugHandle = os.Stdout
	}
	dbg = log.New(debugHandle, "[DEBUG] ", log.Ldate|log.Ltime|log.Lshortfile)
	logErr = log.New(os.Stderr, "[ERROR] ", log.Ldate|log.Ltime|log.Lshortfile)

	service := fmt.Sprint(conf.Host, ":", conf.Port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", service)
	if err != nil {
		logErr.Fatalf("Unable to resolve address: %s\n", err)
	}

	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		logErr.Fatalf("Unable to open a TCP listener: %s\n", err)
	}
	defer listener.Close()

	dbg.Println("Listener started")
	for {
		conn, err := listener.Accept()
		if err != nil {
			logErr.Printf("Unable to start the listener: %s\n", err)
		}
		defer conn.Close()

		// run as a goroutine
		dbg.Printf("Receiving message...\n")
		go HandleClient(conf, conn, logErr)
	}
}

// HandleClient takes care of a client connection.
// Use the PacketHandler parameter to define what you want to do with the
// DataPacket once it is decrypted and trasformed to a DataPacket struct.
// Only the errors will be logged via the logger parameter
func HandleClient(conf *Config, conn net.Conn, logErr *log.Logger) error {
	// close connection on exit
	defer conn.Close()

	// sends the initialization packet
	ipacket, err := NewInitPacket()
	if err != nil {
		logErr.Printf("Unable to create the init packet: %s\n", err)
		return err
	}
	if err = ipacket.Write(conn); err != nil {
		logErr.Printf("Unable to send the init packet: %s\n", err)
		return err
	}

	// Retrieves the data from the client
	data := NewDataPacket(conf.EncryptionMethod, []byte(conf.Password), ipacket)
	if err = data.Read(conn); err != nil {
		logErr.Printf("Unable to read the data packet: %s\n", err)
		return err
	}

	if err = conf.PacketHandler(data); err != nil {
		logErr.Printf("Unable to process the data packet in the custom handler: %s\n", err)
	}
	return err
}
