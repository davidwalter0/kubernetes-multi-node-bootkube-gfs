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
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"k8s.io/client-go/util/cert"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/davidwalter0/transform"
)

// ReadPublicKeysFromPEM is a helper function for reading an array of
// rsa.PublicKey or ecdsa.PublicKey from a PEM-encoded byte array.
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

// ReadPrivateKey is a helper function for reading a private key from
// a PEM-encoded file: k8s.io/kubernetes/pkg/serviceaccount/jwt.go
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
