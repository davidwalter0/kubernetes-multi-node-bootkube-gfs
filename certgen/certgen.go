// Copyright 2018 David Walter.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/kubernetes-incubator/bootkube/pkg/tlsutil"

	"github.com/davidwalter0/go-cfg"
)

const (
	// RSAKeySize bits in key
	RSAKeySize = 2048
	// Duration365d 1 365 day year duration
	Duration365d = time.Hour * 24 * 365
)

var app = &App{}

var err error

func main() {
	if err = cfg.Parse(app); err != nil {
		log.Println(err)
		os.Exit(1)
	}
	app.Dump()
	var ca *CertKeyPair
	var c *CertKeyPair
	var s *Settings

	if s, err = NewSettingsFromApp(app); err != nil {
		app.Debug = true
		app.Dump()
		cfg.Usage()
		log.Fatalf("There was a problem with the arguments %s", err)
	}
	if ca, err = s.GetCA(); err != nil {
		if strings.Index(fmt.Sprintf("%s", err), "PEM file exists") == -1 {
			app.Debug = true
			app.Dump()
		}
		log.Fatalf("There was a problem with the CA %s", err)
	}

	if c, err = s.NewSignedCertKeyPair(ca.Certificate,
		ca.PrivateKey); err != nil {
		if strings.Index(fmt.Sprintf("%s", err), "PEM file exists") == -1 {
			app.Debug = true
			app.Dump()
		}
		log.Fatal(err)
	}

	if err = c.WritePemFormatCertAndKey(); err != nil {
		app.Debug = true
		app.Dump()
		log.Fatal(err)
	}
}

// Load a file to a byte array
func Load(path string) (content []byte, err error) {
	if content, err = ioutil.ReadFile(path); err == nil {
		if err != nil {
			content = nil
		}
	}
	return
}

// LoadPemEncodedCertificate from pem format file
func LoadPemEncodedCertificate(name string) (certificate *x509.Certificate, err error) {
	var content []byte

	if content, err = Load(name); err != nil {
		log.Fatalf("%s\n", err)
	} else {
		certificate, err = tlsutil.ParsePEMEncodedCACert(content)
		if err != nil {
			log.Println("LoadPemEncodedCertificate", name)
			panic(err)
		}
		if app.Debug {
			fmt.Println(Jsonify(certificate))
		}
	}
	return certificate, err
}

// LoadPemEncodedPrivateRSAKey from pem format file
func LoadPemEncodedPrivateRSAKey(name string) (key *rsa.PrivateKey, err error) {
	if k, e := ReadPrivateKey(name); e != nil {
		panic(e)
	} else {
		key = k.(*rsa.PrivateKey)
	}
	if app.Debug {
		fmt.Println(Jsonify(key))
	}
	return
}

// NetIPsFromIPAddresses take an array of IP strings
func NetIPsFromIPAddresses(addresses []string) (ips []net.IP) {
	for _, address := range addresses {
		if ip := net.ParseIP(address); ip != nil {
			ips = append(ips, ip)
		}
	}
	return
}
