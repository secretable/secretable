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

	"golang.org/x/crypto/pbkdf2"
)

var (
	curve    = elliptic.P521
	hashSum  = sha512.Sum512
	hashNew  = sha512.New
	hashSize = sha512.Size

	AESKeySize = 32
	NonceSize  = 12
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

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func SHA512(s string) []byte {
	b := sha512.Sum512([]byte(s))
	return b[:]
}

func GeneratePrivKey() (priv *ecdsa.PrivateKey, err error) {
	priv, err = ecdsa.GenerateKey(curve(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return priv, err

}

func DeriveCipher(password, keySalt []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(
		pbkdf2.Key(password, keySalt, 200000, AESKeySize, hashNew),
	)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func MakeRandom(l int) ([]byte, error) {
	return makeRandom(l)
}
