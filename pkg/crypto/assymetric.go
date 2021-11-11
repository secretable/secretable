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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"

	"github.com/pkg/errors"
)

var (
	ErrPaddingIncorrect = errors.New("padding incorrect")
	ErrInvalidMAC       = errors.New("invalid MAC")
	ErrGenerateEncKey   = errors.New("failed to generate encryption key")
	ErrInvalidPublicKey = errors.New("invalid public key")
	ErrInvalidCipher    = errors.New("invalid ciphertext")
)

func EncryptWithPub(pub *ecdsa.PublicKey, input []byte) (out []byte, err error) {
	ephemeral, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return
	}

	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, ephemeral.D.Bytes())

	if x == nil {
		return nil, ErrGenerateEncKey
	}

	shared := sha512.Sum512(x.Bytes())

	iv, err := makeRandom(16)
	if err != nil {
		return
	}

	paddedIn := addPadding(input)

	encdata, err := encryptCBC(paddedIn, iv, shared[:32])
	if err != nil {
		return
	}

	ephPub := elliptic.Marshal(pub.Curve, ephemeral.PublicKey.X, ephemeral.PublicKey.Y)
	out = make([]byte, 1+len(ephPub)+16)
	out[0] = byte(len(ephPub))
	copy(out[1:], ephPub)
	copy(out[1+len(ephPub):], iv)
	out = append(out, encdata...)

	h := hmac.New(sha512.New, shared[32:])
	h.Write(iv)
	h.Write(encdata)

	return h.Sum(out), nil
}

func DecryptWithPriv(priv *ecdsa.PrivateKey, cipher []byte) (out []byte, err error) {
	if len(cipher) == 0 {
		return nil, ErrInvalidCipher
	}

	ephLen := int(cipher[0])
	ephPub := cipher[1 : 1+ephLen]
	encdata := cipher[1+ephLen:]

	if len(encdata) < (sha512.Size + aes.BlockSize) {
		return nil, ErrInvalidCipher
	}

	x, y := elliptic.Unmarshal(elliptic.P521(), ephPub)
	if x == nil {
		return nil, ErrInvalidPublicKey
	}

	x, _ = priv.Curve.ScalarMult(x, y, priv.D.Bytes())
	if x == nil {
		return nil, ErrGenerateEncKey
	}

	shared := sha512.Sum512(x.Bytes())

	tagStart := len(encdata) - sha512.Size
	h := hmac.New(sha512.New, shared[32:])
	h.Write(encdata[:tagStart])
	mac := h.Sum(nil)

	if !hmac.Equal(mac, encdata[tagStart:]) {
		return nil, ErrInvalidMAC
	}

	paddedOut, err := decryptCBC(encdata[aes.BlockSize:tagStart], encdata[:aes.BlockSize], shared[:32])
	if err != nil {
		return
	}

	return removePadding(paddedOut)
}

func decryptCBC(data, iv, key []byte) (decryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	decryptedData = make([]byte, len(data))
	cipher.NewCBCDecrypter(aesCrypt, iv).
		CryptBlocks(decryptedData, data)

	return
}

func encryptCBC(data, iv, key []byte) (encryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	encryptedData = make([]byte, len(data))
	cipher.NewCBCEncrypter(aesCrypt, iv).
		CryptBlocks(encryptedData, data)

	return
}

func makeRandom(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, errors.Wrap(err, "random read")
	}

	return bytes, nil
}

func removePadding(body []byte) ([]byte, error) {
	l := int(body[len(body)-1])
	if l > 32 {
		return nil, ErrPaddingIncorrect
	}

	return body[:len(body)-l], nil
}

func addPadding(body []byte) []byte {
	l := 32 - len(body)%32
	padding := make([]byte, l)
	padding[l-1] = byte(l)

	return append(body, padding...)
}
