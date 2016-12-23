package nscatools

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
)

var dbg, logErr *log.Logger

// StartServer starts an NSCA server
func StartServer(conf *Config, debug bool) {
	// Initializing logging objects
	debugHandle := ioutil.Discard
	if debug {
		debugHandle = os.Stdout
	}
	dbg = log.New(debugHandle, "[DEBUG] ", log.Ldate|log.Ltime|log.Lshortfile)
	logErr = log.New(os.Stderr, "[ERROR] ", log.Ldate|log.Ltime|log.Lshortfile)

	service := fmt.Sprint(conf.Host, ":", conf.Port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", service)
	checkError(err, true)

	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err, true)
	defer listener.Close()

	dbg.Println("Listener started")
	for {
		conn, err := listener.Accept()
		checkError(err, false)
		defer conn.Close()

		// run as a goroutine
		dbg.Printf("Receiving message...\n")
		go HandleClient(conf, conn)
	}
}

// HandleClient takes care of a client connection.
// Use the PacketHandler parameter to define what you want to do with the
// DataPacket once it is decrypted and trasformed to a DataPacket struct.
func HandleClient(conf *Config, conn net.Conn) error {
	// close connection on exit
	defer conn.Close()

	// sends the initialization packet
	ipacket, err := NewInitPacket(nil, 0)
	if err != nil {
		logErr.Printf("[ERROR] error during the creation of the init packet: %s\n", err)
		return err
	}
	if err = ipacket.Write(conn); err != nil {
		logErr.Printf("[ERROR] While sending the packet: %s\n", err)
		return err
	}

	// Retrieves the data from the client
	data := NewDataPacket(conf.EncryptionMethod, []byte(conf.Password), ipacket.Iv)
	if err = data.Read(conn); err != nil {
		logErr.Printf("[ERROR] error while reading data packet: %s\n", err)
		return err
	}

	if err = conf.PacketHandler(data); err != nil {
		logErr.Printf("[ERROR] error while processing data packet in the custom handler: %s\n", err)
	}
	return err
}

func checkError(err error, exitOnErr bool) {
	if err != nil {
		logErr.Println(err.Error())
		if exitOnErr {
			os.Exit(1)
		}
	}
}
