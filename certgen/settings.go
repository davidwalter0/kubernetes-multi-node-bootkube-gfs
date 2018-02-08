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
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/kubernetes-incubator/bootkube/pkg/tlsutil"
)

// Settings application configuration struct
type Settings struct {
	CAFile    string   `json:"cafile"       doc:"ca cert file name"                    default:"ca"`
	CAKeyFile string   `                    doc:"ca key file name"`
	CertFile  string   `json:"cert"         doc:"cert file name, default:common name"`
	KeyFile   string   `                    doc:"key file name,  default:common name"`
	CACommon  string   `json:"cacommon"     doc:"certificate authority common name"`
	CAOrg     []string `json:"caorg"        doc:"certificate authority comma separated list of organizations"`
	CAOrgUnit []string `json:"caunit"       doc:"certificate authority comma separated list of organizational units"`
	Common    string   `json:"common"       doc:"application certificate common name"`
	DNSNames  []string `json:"dnsnames"     doc:"application certificate comma separated list of dns names"`
	IPs       []net.IP `json:"ips"          doc:"application certificate comma separated list of ip addresses"`
	Org       []string `json:"org"          doc:"application certificate comma separated list of organizations"`
	OrgUnit   []string `json:"unit"         doc:"application certificate comma separated list of organizational units"`
}

// NewSettingsFromApp creates a Settings using app flags or
// environment variables, set the attributes joining path with name +
// ext : set CAFile, CAKeyFile, CertFile, KeyFile
func NewSettingsFromApp(app *App) (s *Settings, err error) {
	s = &Settings{}
	if err = s.ResolvePaths(app); err != nil {
		return nil, err
	}
	s.CACommon = app.CACommon
	s.CAOrg = app.CAOrg
	s.CAOrgUnit = app.CAOrgUnit
	s.Common = app.Common
	s.DNSNames = app.DNSNames
	s.IPs = NetIPsFromIPAddresses(app.IPs)
	s.Org = app.Org
	s.OrgUnit = app.OrgUnit
	return
}

// ResolvePaths complete the paths from partial names
func (s *Settings) ResolvePaths(app *App) error {
	if app.Path == "/" {
		return fmt.Errorf("root (/) or an empty path are not valid")
	}

	if len(app.Path) > 0 {
		base := filepath.Base
		join := filepath.Join

		if len(app.CertFilename) != 0 && len(app.Common) == 0 {
			app.Common = app.CertFilename
		}

		if len(app.CertFilename) == 0 && len(app.Common) != 0 {
			app.CertFilename = app.Common
		}

		if len(app.CertFilename) == 0 && len(app.Common) == 0 {
			return fmt.Errorf("Common name or certfile are required")
		}

		s.CAFile = join(app.Path, base(app.CAFilename)+app.CertExt)
		s.CAKeyFile = join(app.Path, base(app.CAFilename)+app.KeyExt)
		s.CertFile = join(app.Path, base(app.CertFilename)+app.CertExt)
		s.KeyFile = join(app.Path, base(app.CertFilename)+app.KeyExt)
	}

	if _, err := os.Stat(app.Path); os.IsNotExist(err) {
		if err = os.MkdirAll(app.Path, 0700); err != nil {
			return err
		}
	}
	return nil
}

// GetCA create or load cert and key file
func (s *Settings) GetCA() (*CertKeyPair, error) {
	_, caErr := os.Stat(s.CAFile)
	_, keyErr := os.Stat(s.CAKeyFile)
	ca := &CertKeyPair{}
	if caErr == nil && keyErr == nil {
		if !app.ReplaceCA {
			ca.Certificate, err = LoadPemEncodedCertificate(s.CAFile)
			if err != nil {
				return nil, fmt.Errorf("%s PEM file load failed", s.CAFile)
			}
			ca.PrivateKey, err = LoadPemEncodedPrivateRSAKey(s.CAKeyFile)
			if err != nil {
				return nil, fmt.Errorf("%s PEM file load failed", s.CAKeyFile)
			}
			ca.CertFile = s.CAFile
			ca.KeyFile = s.CAKeyFile
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

	ca.CertFile = s.CAFile
	ca.KeyFile = s.CAKeyFile
	ca.SetFingerprint()

	if err = ca.WritePemFormatCertAndKey(); err != nil {
		app.Debug = true
		app.Dump()
		log.Fatal(err)
	}

	return ca, nil
}

// NewKeyAndCert signed certificate
func (s *Settings) NewKeyAndCert(caCert *x509.Certificate, caPrivKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	if !app.Replace {
		_, certErr := os.Stat(s.CertFile)
		_, keyErr := os.Stat(s.KeyFile)

		if certErr == nil {
			return nil, nil, fmt.Errorf("%s PEM file exists and replace not specified", s.CertFile)
		}

		if keyErr == nil {
			return nil, nil, fmt.Errorf("%s PEM file exists and replace not specified", s.KeyFile)
		}
	}
	key, err := tlsutil.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	var altNames = tlsutil.AltNames{
		DNSNames: s.DNSNames,
		IPs:      s.IPs,
	}

	config := tlsutil.CertConfig{
		CommonName:   s.Common,
		Organization: s.Org,
		AltNames:     altNames,
	}
	cert, err := tlsutil.NewSignedCertificate(config, key, caCert, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, err
}

// NewSignedCertKeyPair signed certificate
func (s *Settings) NewSignedCertKeyPair(caCert *x509.Certificate, caPrivKey *rsa.PrivateKey) (*CertKeyPair, error) {
	if !app.Replace {
		_, certErr := os.Stat(s.CertFile)
		_, keyErr := os.Stat(s.KeyFile)

		if certErr == nil {
			return nil, fmt.Errorf("%s PEM file exists and replace not specified", s.CertFile)
		}

		if keyErr == nil {
			return nil, fmt.Errorf("%s PEM file exists and replace not specified", s.KeyFile)
		}
	}

	key, err := tlsutil.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	var altNames = tlsutil.AltNames{
		DNSNames: s.DNSNames,
		IPs:      s.IPs,
	}

	config := tlsutil.CertConfig{
		CommonName:   s.Common,
		Organization: s.Org,
		AltNames:     altNames,
	}
	cert, err := tlsutil.NewSignedCertificate(config, key, caCert, caPrivKey)
	if err != nil {
		return nil, err
	}

	return &CertKeyPair{
		Certificate: cert,
		PrivateKey:  key,
		CertFile:    s.CertFile,
		KeyFile:     s.KeyFile,
		Fingerprint: getFingerprint(cert.Raw),
	}, err
}
