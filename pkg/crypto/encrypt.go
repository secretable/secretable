// Copyright 2021 Mikhail Borovikov and The Secretable Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

const (
	AESKeySize   = 32
	NonceSize    = 12
	NumbIterates = 200000
)

func EncryptWithPhrase(phrase, salt, nonce, plaintext []byte) (cipher []byte, err error) {
	gcm, err := DeriveCipher(phrase, salt)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nil, nonce, plaintext, nil), err
}

func DecryptWithPhrase(phrase, salt, nonce []byte, ciphertext []byte) ([]byte, error) {
	gcm, err := DeriveCipher(phrase, salt)
	if err != nil {
		return nil, err
	}

	b, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, "gcm open")
	}

	return b, nil
}

func SHA512(s string) []byte {
	b := sha512.Sum512([]byte(s))

	return b[:]
}

func GeneratePrivKey() (priv *ecdsa.PrivateKey, err error) {
	priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "ecdsa generate key")
	}

	return priv, nil
}

func DeriveCipher(password, keySalt []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(
		pbkdf2.Key(password, keySalt, NumbIterates, AESKeySize, sha512.New),
	)
	if err != nil {
		return nil, errors.Wrap(err, "aes new cipher")
	}

	c, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "new gcm")
	}

	return c, nil
}

func MakeRandom(l int) ([]byte, error) {
	return makeRandom(l)
}
