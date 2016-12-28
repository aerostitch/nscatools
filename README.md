# Nsca tools library

[![GoDoc](https://godoc.org/github.com/tubemogul/nscatools?status.svg)](http://godoc.org/github.com/tubemogul/nscatools)
[![TravisBuild](https://travis-ci.org/tubemogul/nscatools.svg?branch=master)](https://travis-ci.org/tubemogul/nscatools)

## Introduction

This library is based Nagios's NSCA server but written in Go.

The goal is to have a library to receive the nsca calls and do whatever you want
with the data you receive. Working on that for another application I'm writing.

The technical documentation is available on godoc:
[https://godoc.org/github.com/tubemogul/nscatools](https://godoc.org/github.com/tubemogul/nscatools)

## Usage examples

### Create a NSCA server

This example shows how to use this library to the detail of every packets you
receive. Not very useful as is but simple enough for everybody to understand it.

```golang
package main

import (
  nsrv "github.com/tubemogul/nscatools"
  "log"
  "os"
)

var dbg *log.Logger

func printData(p *nsrv.DataPacket) error {
  dbg.Printf("version: %d\n", p.Version)
  dbg.Printf("crc: %d\n", p.Crc)
  dbg.Printf("timestamp: %d\n", p.Timestamp)
  dbg.Printf("state: %d\n", p.State)
  dbg.Printf("hostname: %s\n", p.HostName)
  dbg.Printf("service: %s\n", p.Service)
  dbg.Printf("Plugin output: %s\n", p.PluginOutput)
  return nil
}

func main() {
  debugHandle := os.Stdout
  dbg = log.New(debugHandle, "[DEBUG] ", log.Ldate|log.Ltime|log.Lshortfile)

  cfg := nsrv.NewConfig("localhost", 5667, nsrv.EncryptXOR, "toto", printData)
  nsrv.StartServer(cfg, true)
}
```

To do functionnal testing, you can, for example, use the following send_nsca.cfg
file:
```
password=toto
encryption_method=1
```

And use the following command:
```sh
echo "myhost mysvc 1 mymessage" | sudo /usr/sbin/send_nsca -H 127.0.0.1 -p 5667 -d ' ' -c send_nsca.cfg
```

### Create a NSCA client

This example shows how to implement a nsca client using this library. You can
use it directly with the running server you created in the previous example.

```golang
package main

import (
  "fmt"
  nsrv "github.com/tubemogul/nscatools"
)

func main() {
  cfg := nsrv.NewConfig("localhost", 5667, nsrv.EncryptXOR, "toto", nil)
  err := nsrv.SendStatus(cfg, "myHost", "my service", nsrv.StateWarning, "You'd better fix me before I go critical")
  if err != nil {
    fmt.Printf("SendStatus returned an error: %s\n", err)
  } else {
    fmt.Println("Packet sent successfuly")
  }
}
```

## Using the Makefile

 * `make lint`: runs golint on your files (requires `github.com/golang/lint/golint` installed)
 * `make fmt`: checks that the files are compliant with the gofmt format
 * `make vet`: runs `go tool vet` on your files to ensure there's no problems
 * `make test`: runs `make lint`, `make fmt`, `make vet` before running all the
   test, printing also the percentage of code coverage
 * `make race`: runs the tests with the `-race` option to detect race conditions
 * `make bench`: runs the benchmarks
 * `make gocov`: runs a gocov report (requires `github.com/axw/gocov/gocov`)
 * `make install`: runs `make test` before running a clean and install
 * `make` / `make all`: run `make test`, `make race` and `make bench`

## Contributions

Contributions to this project are welcome, though please
[file an issue](https://github.com/tubemogul/nscatools/issues/new).
before starting work on anything major as someone else could already be working
on it.

Contributions that do not provide the corresponding tests will not be accepted.
Contributions that do not pass the basic gofmt, vet and other basic checks
provided in the Makefile will not be accepted. It's just a question of trying to
keep a basic code standard. Thanks for your help! :)


## TODO

It is currently a work in progress, so there's a bunch todo. Maybe come back in a
few weeks to get the production-ready version! ;)

* DataPacket:
   * Add and test the check of the crc32 value?
   * Add and test the packet max age check
   * Enc, Dec & test EncryptDES                // DES
   * Enc, Dec & test Encrypt3DES               // 3DES or Triple DES
   * Enc, Dec & test EncryptCAST128            // CAST-128
   * Enc, Dec & test EncryptCAST256            // CAST-256
   * Enc, Dec & test EncryptXTEA               // xTEA
   * Enc, Dec & test Encrypt3WAY               // 3-WAY
   * Enc, Dec & test EncryptBLOWFISH           // SKIPJACK
   * Enc, Dec & test EncryptTWOFISH            // TWOFISH
   * Enc, Dec & test EncryptLOKI97             // LOKI97
   * Enc, Dec & test EncryptRC2                // RC2
   * Enc, Dec & test EncryptARCFOUR            // RC4
   * Enc, Dec & test EncryptRIJNDAEL128        // AES-128
   * Enc, Dec & test EncryptRIJNDAEL192        // AES-192
   * Enc, Dec & test EncryptRIJNDAEL256        // AES-256
   * Enc, Dec & test EncryptWAKE               // WAKE
   * Enc, Dec & test EncryptSERPENT            // SERPENT
   * Enc, Dec & test EncryptENIGMA             // ENIGMA (Unix crypt)
   * Enc, Dec & test EncryptGOST               // GOST
   * Enc, Dec & test EncryptSAFER64            // SAFER-sk64
   * Enc, Dec & test EncryptSAFER128           // SAFER-sk128
   * Enc, Dec & test EncryptSAFERPLUS          // SAFER+
* write examples
* write proper documentation
