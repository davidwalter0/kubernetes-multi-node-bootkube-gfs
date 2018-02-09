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
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"

	"k8s.io/client-go/util/cert"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/davidwalter0/transform"
)

// FingerprintPEM with hash
func FingerprintPEM(pem []byte) (print string) {
	if key, err := GetFirstPEMPublicKey(pem); err == nil {
		print = FingerprintPublicKey(key)
	} else {
		fmt.Println(key)
		panic(err)
	}
	return
}

// FingerprintPublicKey with hash
func FingerprintPublicKey(publicKey interface{}) string {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return FingerprintBigInt(key.N)
	case *dsa.PublicKey:
		return FingerprintBigInt(key.Y)
	case *ecdsa.PublicKey:
		return FingerprintBigInt(key.Y)
	default:
		panic("unknown type of PublicKey key")
	}
}

// Fingerprint Hash of an array of byte ([]byte)
func Fingerprint(text []byte) string {
	hash := sha1.Sum(text)
	return FormatHash(hash[:])
}

// FingerprintBigInt with hash
func FingerprintBigInt(N *big.Int) string {
	var text []byte
	var err error
	if text, err = N.MarshalText(); err != nil {
		return fmt.Sprintf("%s", err)
	}
	hash := sha1.Sum(text)
	return FormatHash(hash[:])
}

// GetFirstPEMPublicKey from a certificate PEM
func GetFirstPEMPublicKey(data []byte) (interface{}, error) {
	var block *pem.Block
	for {
		// read the next block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		// get PEM bytes for just this block
		blockData := pem.EncodeToMemory(block)
		if privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(blockData); err == nil {
			return &privateKey.PublicKey, nil
		}
		if publicKey, err := jwt.ParseRSAPublicKeyFromPEM(blockData); err == nil {
			return publicKey, err
		}
		if privateKey, err := jwt.ParseECPrivateKeyFromPEM(blockData); err == nil {
			return &privateKey.PublicKey, err
		}
		if publicKey, err := jwt.ParseECPublicKeyFromPEM(blockData); err == nil {
			return publicKey, err
		}
	}
	return nil, fmt.Errorf("No rsa.PublicKey parsed from certificate PEM")
}

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

// FormatHash colon separated hex formatted string
func FormatHash(hash []byte) string {
	hexified := make([][]byte, len(hash))
	for i, data := range hash {
		hexified[i] = []byte(fmt.Sprintf("%02X", data))
	}
	return string(bytes.Join(hexified, []byte(":")))
}
