package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/kubernetes-incubator/bootkube/pkg/tlsutil"
)

// CertKeyPair cert and key
type CertKeyPair struct {
	*x509.Certificate
	*rsa.PrivateKey
	CertFile        string
	KeyFile         string
	CertFingerprint string
	KeyFingerprint  string
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
		log.Printf("Wrote %s\n", c.CertFile)
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

// PrintFingerprint key
func PrintFingerprint(key string) {
	fmt.Printf("fingerprint=%s", key)
}

func getFingerprint(der []byte) string {
	hash := sha1.Sum(der)
	return FormatHash(hash[:])
}

// GetKeyFingerprint from a certificate, doesn't match ssh key print
func (c *CertKeyPair) GetKeyFingerprint() string {
	return c.KeyFingerprint
}

// SetKeyFingerprint from a certificate
func (c *CertKeyPair) SetKeyFingerprint() {
	c.KeyFingerprint = FingerprintPublicKey(c.PrivateKey.Public())
}

// GetFingerprint from a certificate
func (c *CertKeyPair) GetCertFingerprint() string {
	return c.CertFingerprint
}

// SetFingerprint from a certificate
func (c *CertKeyPair) SetCertFingerprint() {
	c.CertFingerprint = FingerprintPublicKey(c.Certificate.PublicKey)
}
