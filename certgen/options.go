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
	"log"
	"os"
)

// App application suration struct
type App struct {
	Debug        bool     `json:"debug"           doc:"be more verbose"`
	Fingerprint  bool     `json:"fingerprint"     doc:"fingerprint existing cert and key"                      default:"true"`
	Replace      bool     `json:"replace"         doc:"replace existing cert and key"                          default:"false"`
	ReplaceCA    bool     `json:"replace-ca"      doc:"replace CA if present, create if not"                   default:"false"`
	KeyExt       string   `json:"key-ext"         doc:"key certificate filename extension"                     default:".key"`
	CertExt      string   `json:"cert-ext"        doc:"cert certificate filename extension"                    default:".crt"`
	Path         string   `json:"path"            doc:"path to certficates"                                    default:"cluster/tls"`
	CACommon     string   `json:"ca-common"       doc:"certificate authority common name"`
	CAFilename   string   `json:"ca-filename"     doc:"ca cert/key file name sans extension"                   default:"ca"`
	CAOrg        []string `json:"ca-org"          doc:"certificate authority comma separated list of organizations"`
	CAOrgUnit    []string `json:"ca-unit"         doc:"certificate authority comma separated list of organizational units"`
	CertFilename string   `json:"cert-filename"   doc:"cert/key file name sans extension, default(common name)"`
	Common       string   `json:"common"          doc:"application certificate common name"`
	DNSNames     []string `json:"dnsnames"        doc:"application certificate comma separated list of dns names"`
	IPs          []string `json:"ips"             doc:"application certificate comma separated list of ip addresses"`
	Org          []string `json:"org"             doc:"application certificate comma separated list of organizations"`
	OrgUnit      []string `json:"unit"            doc:"application certificate comma separated list of organizational units"`
}

// Dump info from struct
func (app *App) Dump() {
	if app.Debug {
		var j = []byte{}
		if j, err = json.MarshalIndent(app, "", "  "); err != nil {
			log.Println(err)
			os.Exit(1)
		}
		log.Println(string(j))
	}
}
