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
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	Debug       bool     `json:"debug"        doc:"be more verbose"`
	Fingerprint bool     `json:"fingerprint"  doc:"fingerprint existing cert and key"    default:"true"`
	Replace     bool     `json:"replace"      doc:"replace existing cert and key"        default:"false"`
	ReplaceCA   bool     `json:"replaceca"    doc:"replace CA if present, create if not" default:"false"`
	KeyExt      string   `json:"keyext"       doc:"key filename extension"               default:".key"`
	CertExt     string   `json:"certext"      doc:"cert filename extension"              default:".crt"`
	Path        string   `json:"path"         doc:"path to certficates"                  default:"cluster/tls"`
	CAFile      string   `json:"cafile"       doc:"ca cert file name"                    default:"ca"`
	CAKeyFile   string   `                    doc:"ca key file name"`
	CertFile    string   `json:"cert"         doc:"cert file name, default:common name"`
	KeyFile     string   `                    doc:"key file name,  default:common name"`
	CACommon    string   `json:"cacommon"     doc:"certificate authority common name"`
	CAOrg       []string `json:"caorg"        doc:"certificate authority comma separated list of organizations"`
	CAOrgUnit   []string `json:"caunit"       doc:"certificate authority comma separated list of organizational units"`
	Common      string   `json:"common"       doc:"application certificate common name"`
	DNSNames    []string `json:"dnsnames"     doc:"application certificate comma separated list of dns names"`
	IPs         []string `json:"ips"          doc:"application certificate comma separated list of ip addresses"`
	Org         []string `json:"org"          doc:"application certificate comma separated list of organizations"`
	OrgUnit     []string `json:"unit"         doc:"application certificate comma separated list of organizational units"`
}

var app = &App{}
var err error

// CertKeyPair cert and key
type CertKeyPair struct {
	*x509.Certificate
	*rsa.PrivateKey
	CertFile    string
	KeyFile     string
	Fingerprint string
}

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

	if err = app.PathCheck(); err != nil {
		app.Debug = true
		printConfig()
		log.Fatal(err)
	}
	var ca *CertKeyPair
	var c *CertKeyPair

	if ca, err = app.GetCA(); err != nil {
		if strings.Index(fmt.Sprintf("%s", err), "PEM file exists") == -1 {
			app.Debug = true
			printConfig()
		}
		log.Fatalf("There was a problem with the CA %s", err)
	}

	if c, err = app.NewSignedCertKeyPair(ca.Certificate,
		ca.PrivateKey); err != nil {
		if strings.Index(fmt.Sprintf("%s", err), "PEM file exists") == -1 {
			app.Debug = true
			printConfig()
		}
		log.Fatal(err)
	}

	if err = c.WritePemFormatCertAndKey(); err != nil {
		app.Debug = true
		printConfig()
		log.Fatal(err)
	}

	// var cert = ca.Certificate
	// var key = ca.PrivateKey

	// WritePemFormatCertAndKey(app.CAFile, app.CAKeyFile, cert, key)
	// if !app.ReplaceCA {
	// 	cert, key, err = app.NewKeyAndCert(ca.Certificate, ca.PrivateKey)
	// 	WritePemFormatCertAndKey(app.Cert, app.Key, cert, key)
	// }
}

// GetCA create or load cert and key file
func (app *App) GetCA() (*CertKeyPair, error) {
	_, caErr := os.Stat(app.CAFile)
	_, keyErr := os.Stat(app.CAKeyFile)
	ca := &CertKeyPair{}
	if app.ReplaceCA {
		if caErr == nil && keyErr == nil {
			ca.Certificate, err = LoadPemEncodedCertificate(app.CAFile)
			if err != nil {
				return nil, fmt.Errorf("%s PEM file load failed", app.CAFile)
			}
			ca.PrivateKey, err = LoadPemEncodedPrivateRSAKey(app.CAKeyFile)
			if err != nil {
				return nil, fmt.Errorf("%s PEM file load failed", app.CAKeyFile)
			}
			ca.CertFile = app.CAFile
			ca.KeyFile = app.CAKeyFile
			ca.SetFingerprint()
			return ca, nil
		}
	}
	key, err := tlsutil.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	ca.PrivateKey = key

	var certConfig = tlsutil.CertConfig{
		CommonName:         app.CACommon,
		Organization:       app.CAOrg,
		OrganizationalUnit: app.CAOrgUnit,
		AltNames: tlsutil.AltNames{
			DNSNames: app.DNSNames,
			IPs:      NetIPsFromIPAddresses(app.IPs),
		},
	}

	ca.Certificate, err =
		tlsutil.NewSelfSignedCACertificate(certConfig, ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	ca.CertFile = app.CAFile
	ca.KeyFile = app.CAKeyFile
	ca.SetFingerprint()

	if err = ca.WritePemFormatCertAndKey(); err != nil {
		app.Debug = true
		printConfig()
		log.Fatal(err)
	}

	return ca, nil
}

// WritePemFormatCertAndKey from in memory objects
func (c *CertKeyPair) WritePemFormatCertAndKey() (err error) {

	if len(c.CertFile) == 0 {
		err = errors.New("CertFile name empty")
		panic(err)
	}

	if len(c.KeyFile) == 0 {
		err = errors.New("KeyFile name empty")
		panic(err)
	}

	if c.Certificate == nil {
		err = errors.New("Certificate empty")
		panic(err)
	}

	if c.PrivateKey == nil {
		err = errors.New("PrivateKey empty")
		panic(err)
	}

	// Public key
	if certOut, err := os.Create(c.CertFile); err == nil {
		defer certOut.Close()
		certOut.Write(tlsutil.EncodeCertificatePEM(c.Certificate))
		log.Printf("Wrote %s : %s\n", c.CertFile, c.GetFingerprint())
	} else {
		return err
	}

	// Private key
	if keyOut, err := os.OpenFile(c.KeyFile,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); err == nil {
		defer keyOut.Close()
		keyOut.Write(tlsutil.EncodePrivateKeyPEM(c.PrivateKey))
		log.Printf("Wrote %s\n", c.KeyFile)
	} else {
		return err
	}
	return nil
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

// SetFingerprint from a certificate
func (c *CertKeyPair) SetFingerprint() {
	c.Fingerprint = getFingerprint(c.Certificate.Raw)
}

// WritePemFormatCertAndKey from in memory objects
func WritePemFormatCertAndKey(certFile, keyFile string, cert *x509.Certificate, key *rsa.PrivateKey) {
	// Public key
	if certOut, err := os.Create(certFile); err != nil {
		panic(err)
	} else {
		certOut.Write(tlsutil.EncodeCertificatePEM(cert))
		certOut.Close()
		log.Printf("Wrote %s : %s\n", certFile, getFingerprint(cert.Raw))
	}
	// Private key
	if keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); err != nil {
		panic(err)
	} else {
		keyOut.Write(tlsutil.EncodePrivateKeyPEM(key))
		keyOut.Close()
		log.Printf("Wrote %s\n", keyFile)
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

// GetCA create or load cert and key file
func GetCA() (*CertKeyPair, error) { //(*x509.Certificate, *tls.Certificate) {
	_, caErr := os.Stat(app.CAFile)
	_, keyErr := os.Stat(app.CAKeyFile)
	ca := &CertKeyPair{}
	if caErr == nil && keyErr == nil {
		ca.Certificate, err = LoadPemEncodedCertificate(app.CAFile)
		if err != nil {
			return nil, fmt.Errorf("%s PEM file load failed", app.CAFile)
		}
		ca.PrivateKey, err = LoadPemEncodedPrivateRSAKey(app.CAKeyFile)
		if err != nil {
			return nil, fmt.Errorf("%s PEM file load failed", app.CAKeyFile)
		}
		return ca, nil
	}
	key, err := tlsutil.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	ca.PrivateKey = key

	var certConfig = tlsutil.CertConfig{
		CommonName:         app.CACommon,
		Organization:       app.CAOrg,
		OrganizationalUnit: app.CAOrgUnit,
		AltNames: tlsutil.AltNames{
			DNSNames: app.DNSNames,
			IPs:      NetIPsFromIPAddresses(app.IPs),
		},
	}

	ca.Certificate, err =
		tlsutil.NewSelfSignedCACertificate(certConfig, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	return ca, nil
}

// NewKeyAndCert signed certificate
func (app *App) NewKeyAndCert(caCert *x509.Certificate, caPrivKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	if !app.Replace {
		_, certErr := os.Stat(app.CertFile)
		_, keyErr := os.Stat(app.KeyFile)

		if certErr == nil {
			return nil, nil, fmt.Errorf("%s PEM file exists and replace not specified", app.CertFile)
		}

		if keyErr == nil {
			return nil, nil, fmt.Errorf("%s PEM file exists and replace not specified", app.KeyFile)
		}
	}
	key, err := tlsutil.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	var altNames = tlsutil.AltNames{
		DNSNames: app.DNSNames,
		IPs:      NetIPsFromIPAddresses(app.IPs),
	}

	config := tlsutil.CertConfig{
		CommonName:   app.Common,
		Organization: app.Org,
		AltNames:     altNames,
	}
	cert, err := tlsutil.NewSignedCertificate(config, key, caCert, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, err
}

// NewSignedCertKeyPair signed certificate
func (app *App) NewSignedCertKeyPair(caCert *x509.Certificate, caPrivKey *rsa.PrivateKey) (*CertKeyPair, error) {
	if !app.Replace {
		_, certErr := os.Stat(app.CertFile)
		_, keyErr := os.Stat(app.KeyFile)

		if certErr == nil {
			return nil, fmt.Errorf("%s PEM file exists and replace not specified", app.CertFile)
		}

		if keyErr == nil {
			return nil, fmt.Errorf("%s PEM file exists and replace not specified", app.KeyFile)
		}
	}

	key, err := tlsutil.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	var altNames = tlsutil.AltNames{
		DNSNames: app.DNSNames,
		IPs:      NetIPsFromIPAddresses(app.IPs),
	}

	config := tlsutil.CertConfig{
		CommonName:   app.Common,
		Organization: app.Org,
		AltNames:     altNames,
	}
	cert, err := tlsutil.NewSignedCertificate(config, key, caCert, caPrivKey)
	if err != nil {
		return nil, err
	}

	return &CertKeyPair{
		Certificate: cert,
		PrivateKey:  key,
		CertFile:    app.CertFile,
		KeyFile:     app.KeyFile,
		Fingerprint: getFingerprint(cert.Raw),
	}, err
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

// PathCheck validate and fixup the destination path for certs
func (app *App) PathCheck() error {
	if app.Path == "/" {
		log.Fatalf("root (/) or an empty path are not valid")
	}

	if len(app.Path) > 0 {
		base := filepath.Base
		join := filepath.Join

		if len(app.CertFile) != 0 && len(app.Common) == 0 {
			app.Common = app.CertFile
		}

		if len(app.CertFile) == 0 && len(app.Common) != 0 {
			app.CertFile = app.Common
		}

		if len(app.CertFile) == 0 && len(app.Common) == 0 {
			return fmt.Errorf("Common name or certfile are required")
		}
		var filename = app.CertFile
		var cafilename = app.CAFile
		app.CAFile = join(app.Path, base(cafilename)+app.CertExt)
		app.CAKeyFile = join(app.Path, base(cafilename)+app.KeyExt)
		app.CertFile = join(app.Path, base(filename)+app.CertExt)
		app.KeyFile = join(app.Path, base(filename)+app.KeyExt)
	}

	if _, err := os.Stat(app.Path); os.IsNotExist(err) {
		if err = os.MkdirAll(app.Path, 0700); err != nil {
			return err
		}
	}
	return nil
}
