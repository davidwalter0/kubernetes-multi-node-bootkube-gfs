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

type funcReturnsErr func() error

func checkErr(f funcReturnsErr) {
	if err := f(); err != nil {
		log.Println(err)
	}
}

// WritePemFormatCertAndKey from in memory objects
func (c *CertKeyPair) WritePemFormatCertAndKey() (err error) {
	if c == nil {
		err = errors.New("c is nil")
		return
	}
	if len(c.CertFile) == 0 {
		err = errors.New("CertFile name empty")
		return
	}

	if len(c.KeyFile) == 0 {
		err = errors.New("KeyFile name empty")
		return
	}

	if c.Certificate == nil {
		err = errors.New("Certificate empty")
		return
	}

	if c.PrivateKey == nil {
		err = errors.New("PrivateKey empty")
		return
	}

	// Public key
	if certOut, err := os.Create(c.CertFile); err == nil {
		defer checkErr(certOut.Close)
		if _, err = certOut.Write(tlsutil.EncodeCertificatePEM(c.Certificate)); err != nil {
			return err
		}
		log.Printf("Wrote %s\n", c.CertFile)
	} else {
		return err
	}
	// Private key
	if keyOut, err := os.OpenFile(c.KeyFile,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); err == nil {
		defer checkErr(keyOut.Close)
		if _, err = keyOut.Write(tlsutil.EncodePrivateKeyPEM(c.PrivateKey)); err != nil {
			return err
		}
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
	c.KeyFingerprint = FingerprintMd5(c.PrivateKey.Public().(*rsa.PublicKey))
}

// GetCertFingerprint from a certificate
func (c *CertKeyPair) GetCertFingerprint() string {
	return c.CertFingerprint
}

// SetCertFingerprint from a certificate
func (c *CertKeyPair) SetCertFingerprint() {
	c.CertFingerprint = FingerprintMd5(c.Certificate.PublicKey.(*rsa.PublicKey))
}
