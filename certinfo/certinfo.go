package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/grantae/certinfo"
	"io/ioutil"
	"log"
	"os"

	"github.com/davidwalter0/go-cfg"
)

type App struct {
	File        string
	Fingerprint bool
	Debug       bool
}

// CertKeyPair cert and key
type CertKeyPair struct {
	*x509.Certificate
	*rsa.PrivateKey
	CertFile    string
	KeyFile     string
	Fingerprint string
}

var app = &App{}
var err error

func printConfig() {
	if app.Debug {
		var j = []byte{}
		if j, err = json.MarshalIndent(app, "", "  "); err != nil {
			log.Println(err)
			os.Exit(1)
		}
		log.Println(string(j))
	}
}

func main() {
	if err = cfg.Parse(app); err != nil {
		log.Println(err)
		os.Exit(1)
	}

	printConfig()
	if app.File == "" {
		cfg.Usage()
		os.Exit(-1)
	}

	// Read and parse the PEM certificate file
	pemData, err := ioutil.ReadFile(app.File)
	if err != nil {
		log.Fatal(err)
	}
	block, rest := pem.Decode([]byte(pemData))
	if block == nil || len(rest) > 0 {
		log.Fatal("Certificate decoding error")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	if app.Fingerprint {
		c := &CertKeyPair{
			CertFile:    app.File,
			Certificate: cert,
		}
		c.Fingerprint = getFingerprint(c.Certificate.Raw)
		log.Printf("%s : %s\n", c.CertFile, c.GetFingerprint())
	} else {
		// Print the certificate
		result, err := certinfo.CertificateText(cert)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(result)
	}
}

func getFingerprint(der []byte) string {
	hash := sha1.Sum(der)
	hexified := make([][]byte, len(hash))
	for i, data := range hash {
		hexified[i] = []byte(fmt.Sprintf("%02X", data))
	}
	return fmt.Sprintf("SHA1 Fingerprint=%s", string(bytes.Join(hexified, []byte(":"))))
}

// GetFingerprint from a certificate
func (c *CertKeyPair) GetFingerprint() string {
	return c.Fingerprint
}
