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
	"errors"
)

func EncryptWithPub(pub *ecdsa.PublicKey, in []byte) (out []byte, err error) {
	ephemeral, err := ecdsa.GenerateKey(curve(), rand.Reader)
	if err != nil {
		return
	}
	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, ephemeral.D.Bytes())
	if x == nil {
		return nil, errors.New("failed to generate encryption key")
	}
	shared := hashSum(x.Bytes())
	iv, err := makeRandom(16)
	if err != nil {
		return
	}

	paddedIn := addPadding(in)
	ct, err := encryptCBC(paddedIn, iv, shared[:32])
	if err != nil {
		return
	}

	ephPub := elliptic.Marshal(pub.Curve, ephemeral.PublicKey.X, ephemeral.PublicKey.Y)
	out = make([]byte, 1+len(ephPub)+16)
	out[0] = byte(len(ephPub))
	copy(out[1:], ephPub)
	copy(out[1+len(ephPub):], iv)
	out = append(out, ct...)

	h := hmac.New(hashNew, shared[32:])
	h.Write(iv)
	h.Write(ct)
	out = h.Sum(out)
	return
}

func DecryptWithPriv(priv *ecdsa.PrivateKey, in []byte) (out []byte, err error) {
	if len(in) == 0 {
		return nil, errors.New("invalid ciphertext")
	}
	ephLen := int(in[0])
	ephPub := in[1 : 1+ephLen]
	ct := in[1+ephLen:]
	if len(ct) < (hashSize + aes.BlockSize) {
		return nil, errors.New("invalid ciphertext")
	}

	x, y := elliptic.Unmarshal(curve(), ephPub)
	if x == nil {
		return nil, errors.New("invalid public key")
	}

	x, _ = priv.Curve.ScalarMult(x, y, priv.D.Bytes())
	if x == nil {
		return nil, errors.New("failed to generate encryption key")
	}
	shared := hashSum(x.Bytes())

	tagStart := len(ct) - hashSize
	h := hmac.New(hashNew, shared[32:])
	h.Write(ct[:tagStart])
	mac := h.Sum(nil)
	if !hmac.Equal(mac, ct[tagStart:]) {
		return nil, errors.New("invalid MAC")
	}

	paddedOut, err := decryptCBC(ct[aes.BlockSize:tagStart], ct[:aes.BlockSize], shared[:32])
	if err != nil {
		return
	}
	out, err = removePadding(paddedOut)
	return
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
	_, err := rand.Read(bytes)
	return bytes, err
}

func removePadding(b []byte) ([]byte, error) {
	l := int(b[len(b)-1])
	if l > 32 {
		return nil, errors.New("padding incorrect")
	}

	return b[:len(b)-l], nil
}

func addPadding(b []byte) []byte {
	l := 32 - len(b)%32
	padding := make([]byte, l)
	padding[l-1] = byte(l)
	return append(b, padding...)
}
