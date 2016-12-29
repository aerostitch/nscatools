package nscatools

import (
	"fmt"
	"net"
	"time"
)

// SendStatus connects to the nsca server and sends the provided data in the
// right format. If you want to send a host status (as opposed to a service
// status), just let the "service" parameter empty
func SendStatus(conf *Config, clientHost string, service string, status int16, message string) error {

	nscaServer := fmt.Sprint(conf.Host, ":", conf.Port)
	conn, err := net.DialTimeout("tcp", nscaServer, 10*time.Second)
	if err != nil {
		return fmt.Errorf("unable to connect to the provided server: %s", err)
	}
	defer conn.Close()

	ipkt, err := NewInitPacket()
	if err = ipkt.Read(conn); err != nil {
		return fmt.Errorf("unable to read the initialization vector: %s", err)
	}

	dp := NewDataPacket(conf.EncryptionMethod, []byte(conf.Password), ipkt)
	dp.HostName = clientHost
	dp.Service = service
	dp.State = status
	dp.PluginOutput = message
	if err = dp.Write(conn); err != nil {
		return fmt.Errorf("unable to Send the packet: %s", err)
	}
	return nil
}
