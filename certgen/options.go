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
	"encoding/json"
	"fmt"
	"log"
	"os"

	yaml "gopkg.in/yaml.v2"
)

// App application struct
type App struct {
	Fingerprint bool     `json:"fingerprint" doc:"fingerprint existing cert and key"    default:"false"`
	DumpCfg     bool     `json:"dumpcfg"     doc:"dump config and exit"`
	JSONCfg     string   `json:"jsoncfg"     doc:"file with json definition"`
	YamlCfg     string   `json:"yamlcfg"     doc:"file with yaml definition"`
	Debug       bool     `json:"debug"       doc:"be more verbose"`
	Replace     bool     `json:"replace"     doc:"replace existing cert and key"        default:"false"`
	ReplaceCA   bool     `json:"replace-ca"  doc:"replace CA if present, create if not" default:"false"`
	KeyExt      string   `json:"key-ext"     doc:"key certificate filename extension"   default:".key"`
	CertExt     string   `json:"cert-ext"    doc:"cert certificate filename extension"  default:".crt"`
	Path        string   `json:"path"        doc:"path to certficates"                  default:"cluster/tls"`
	CACommon    string   `json:"ca-common"   doc:"CA common name"`
	CAFilename  string   `json:"ca-filename" doc:"ca cert/key file name sans extension" default:"ca"`
	CAOrg       []string `json:"ca-org"      doc:"CA commaized list of org"`
	CAOrgUnit   []string `json:"ca-unit"     doc:"CA commaized list of org units"`
	CertFile    string   `json:"cert-file"   doc:"cert/key file name sans extension, default(common name)"`
	Common      string   `json:"common"      doc:"app cert common name"`
	DNSNames    []string `json:"dnsnames"    doc:"app cert commaized list of dns names"`
	IPs         []string `json:"ips"         doc:"app cert commaized list of ip addresses"`
	Org         []string `json:"org"         doc:"app cert commaized list of org"`
	OrgUnit     []string `json:"unit"        doc:"app cert commaized list of org units"`
}

// Dump info from struct
func (app *App) Dump() {
	if app.Debug || app.DumpCfg {
		var j = []byte{}
		if j, err = json.MarshalIndent(app, "", "  "); err != nil {
			log.Println(err)
			os.Exit(1)
		}
		fmt.Println(string(j))
	}
	if app.DumpCfg {
		os.Exit(0)
	}
}

// ParseCfg from a file to initialize the certificate definition
func (app *App) ParseCfg() error {
	if len(app.YamlCfg) > 0 && len(app.JSONCfg) > 0 {
		return fmt.Errorf("Use --yamlcfg or --jsoncfg not both")
	}
	if len(app.YamlCfg) > 0 {
		text, err := Load(app.YamlCfg)
		if err != nil {
			return err
		}
		if err = yaml.Unmarshal(text, app); err != nil {
			return err
		}
	}

	if len(app.JSONCfg) > 0 {
		text, err := Load(app.JSONCfg)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(text, app); err != nil {
			return err
		}
	}

	return nil
}
