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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"k8s.io/client-go/util/cert"

	"github.com/kubernetes-incubator/bootkube/pkg/tlsutil"

	"github.com/davidwalter0/go-cfg"
	"github.com/davidwalter0/transform"
)

const (
	// RSAKeySize bits in key
	RSAKeySize = 2048
	// Duration365d 1 365 day year duration
	Duration365d = time.Hour * 24 * 365
)

// App application configuration struct
type App struct {
	CertificateAuthorityFile    string   `json:"cafile"       doc:"ca cert file path"     default:"cluster/tls/ca.crt"`
	CertificateAuthorityKeyFile string   `json:"cakey"        doc:"ca key file path"      default:"cluster/tls/ca.key"`
	DNSNames                    []string `json:"dnsnames"     doc:"comma separated list of dns names"`
	IPs                         []string `json:"ips"          doc:"comma separated list of ip addresses"`
	CommonName                  string   `json:"common"       doc:"common name"`
	Certificate                 string   `json:"cert"         doc:"client cert file path" default:"cluster/tls/application.crt"`
	CertificateKey              string   `json:"key"          doc:"client key file path"  default:"cluster/tls/application.key"`
	Organization                []string `json:"organization" doc:"comma separated list of organizations"`
	Debug                       bool

	// PostalCode         []string `json:"postal-code"   doc:"comma separated list of postal codes"`
	// OrganizationalUnit []string `json:"organizational-unit"  doc:"comma separated list of organizational-units"`
	// Country    []string `json:"country"       doc:"comma separated list of country abbreviations"`
	// Province   []string `json:"province"      doc:"comma separated list of provinces"`
	// Locality   []string `json:"locality"      doc:"comma separated list of localities"`
	// Address    []string `json:"address"       doc:"comma separated list of street addresses"`
}

var app = &App{}
var err error

type CertificateAuthority struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

func printConfig() {
	var j = []byte{}
	if j, err = json.MarshalIndent(app, "", "  "); err != nil {
		log.Println(err)
		os.Exit(1)
	}
	log.Println(string(j))
}

func main() {
	if err = cfg.Parse(app); err != nil {
		log.Println(err)
		os.Exit(1)
	}
	if app.Debug {
		printConfig()
	}
	certificateAuthority := &CertificateAuthority{}

	certificateAuthority.Certificate, err = LoadPemEncodedCertificate(app.CertificateAuthorityFile)
	certificateAuthority.PrivateKey, err = LoadPemEncodedPrivateRSAKey(app.CertificateAuthorityKeyFile)

	// fmt.Println(certificateAuthority.Certificate)
	// fmt.Println(certificateAuthority.PrivateKey)
	var key *rsa.PrivateKey
	var cert *x509.Certificate
	key, cert, err = app.NewKeyAndCert(certificateAuthority.Certificate, certificateAuthority.PrivateKey)
	WritePemFormatKeyandCert(key, cert)
}

// WritePemFormatKeyandCert from in memory objects
func WritePemFormatKeyandCert(key *rsa.PrivateKey, cert *x509.Certificate) {
	// Public key
	if certOut, err := os.Create(app.Certificate); err != nil {
		panic(err)
	} else {
		// pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		certOut.Write(tlsutil.EncodeCertificatePEM(cert))
		certOut.Close()
		log.Printf("Wrote %s\n", app.Certificate)
	}
	// Private key
	if keyOut, err := os.OpenFile(app.CertificateKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); err != nil {
		panic(err)
	} else {
		// pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		keyOut.Write(tlsutil.EncodePrivateKeyPEM(key))
		keyOut.Close()
		log.Printf("Wrote %s\n", app.CertificateKey)
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

// NewKeyAndCert signed certificate
func (app *App) NewKeyAndCert(caCert *x509.Certificate, caPrivKey *rsa.PrivateKey) (*rsa.PrivateKey, *x509.Certificate, error) {

	key, err := tlsutil.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	var altNames = tlsutil.AltNames{
		DNSNames: app.DNSNames,
		IPs:      NetIPsFromIPAddresses(app.IPs),
	}
	fmt.Println(altNames.DNSNames)
	fmt.Println(altNames.IPs)
	// for _, addr := range addrs {
	// 	if ip := net.ParseIP(addr); ip != nil {
	// 		altNames.IPs = append(altNames.IPs, ip)
	// 	} else {
	// 		altNames.DNSNames = append(altNames.DNSNames, addr)
	// 	}
	// }

	config := tlsutil.CertConfig{
		CommonName:   app.CommonName,
		Organization: app.Organization,
		AltNames:     altNames,
	}
	cert, err := tlsutil.NewSignedCertificate(config, key, caCert, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, err
}

// Jsonify an object
func Jsonify(data interface{}) string {
	var err error
	data, err = transform.TransformData(data)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	s, err := json.MarshalIndent(data, "", "  ") // spaces)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	return string(s)
}

// k8s.io/kubernetes/pkg/serviceaccount/jwt.go

// ReadPublicKeysFromPEM is a helper function for reading an array of rsa.PublicKey or ecdsa.PublicKey from a PEM-encoded byte array.
// Reads public keys from both public and private key files.
func ReadPublicKeysFromPEM(data []byte) ([]interface{}, error) {
	var block *pem.Block
	keys := []interface{}{}
	for {
		// read the next block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		// get PEM bytes for just this block
		blockData := pem.EncodeToMemory(block)
		if privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(blockData); err == nil {
			keys = append(keys, &privateKey.PublicKey)
			continue
		}
		if publicKey, err := jwt.ParseRSAPublicKeyFromPEM(blockData); err == nil {
			keys = append(keys, publicKey)
			continue
		}

		if privateKey, err := jwt.ParseECPrivateKeyFromPEM(blockData); err == nil {
			keys = append(keys, &privateKey.PublicKey)
			continue
		}
		if publicKey, err := jwt.ParseECPublicKeyFromPEM(blockData); err == nil {
			keys = append(keys, publicKey)
			continue
		}

		// tolerate non-key PEM blocks for backwards compatibility
		// originally, only the first PEM block was parsed and expected to be a key block
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("data does not contain a valid RSA or ECDSA key")
	}
	return keys, nil
}

// k8s.io/kubernetes/pkg/serviceaccount/jwt.go

// ReadPrivateKey is a helper function for reading a private key from a PEM-encoded file
func ReadPrivateKey(file string) (interface{}, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	key, err := cert.ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file %s: %v", file, err)
	}
	return key, nil
}
