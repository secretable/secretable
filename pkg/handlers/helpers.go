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

package handlers

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"html"
	"secretable/pkg/crypto"
	"secretable/pkg/log"
	"secretable/pkg/tables"
	"time"

	"github.com/mr-tron/base58/base58"
	"github.com/pkg/errors"
	tb "gopkg.in/tucnak/telebot.v2"
)

var (
	ErrMissingKey    = errors.New("missing private key")
	ErrInvalidFormat = errors.New("invalid format")
)

func (h *Handler) sendMessage(m *tb.Message, msg string) {
	resp, err := h.Bot.Send(m.Chat, msg, tb.Silent, tb.ModeHTML)
	if err != nil {
		log.Error("Unable to send a message to telegram: "+err.Error(), "chat_id", m.Chat.ID, "message", msg)

		return
	}

	go cleanupMessage(h.Bot, resp, h.Config.CleanupTimeout)
}

func (h *Handler) sendMessageWithoutCleanup(m *tb.Message, msg string) {
	_, err := h.Bot.Send(m.Chat, msg, tb.Silent, tb.ModeHTML)
	if err != nil {
		log.Error("Unable to send a message to telegram"+err.Error(), "chat_id", m.Chat.ID, "message", msg)

		return
	}
}

func (h *Handler) hasAccess(msg *tb.Message) bool {
	id := fmt.Sprint(msg.Chat.ID)
	for _, a := range h.Config.AllowedList {
		if a == id {
			return true
		}
	}

	h.sendMessage(msg, "Access forbidden")

	return false
}

func getPrivkeyAsBytes(tp *tables.TablesProvider, salt, masterPass string) ([]byte, bool, error) {
	k := tp.GetKey()

	key, err := base58.Decode(k)
	if err != nil {
		return nil, false, errors.Wrap(err, "base58 decode")
	}

	if len(key) < crypto.NonceSize {
		return nil, false, ErrInvalidFormat
	}

	nonce := key[:crypto.NonceSize]
	encprivkey := key[crypto.NonceSize:]

	decPrivkey, err := crypto.DecryptWithPhrase([]byte(masterPass), []byte(salt), nonce, encprivkey)
	if err != nil {
		return nil, false, errors.Wrap(err, "decrypt with phrase")
	}

	return decPrivkey, true, nil
}

func getPrivkey(tp *tables.TablesProvider, salt, masterPass string) (*ecdsa.PrivateKey, error) {
	decPrivkey, ok, err := getPrivkeyAsBytes(tp, salt, masterPass)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, ErrMissingKey
	}

	privkey, err := x509.ParsePKCS8PrivateKey(decPrivkey)
	if err != nil {
		return nil, errors.Wrap(err, "parse pkcs8")
	}

	return privkey.(*ecdsa.PrivateKey), nil
}

func makeQueryResponse(index int, secret tables.SecretsData) string {
	return fmt.Sprintf("(%d) <b>%s</b>\n<code>%s</code>\n<code>%s</code>",
		index,
		html.EscapeString(secret.Description),
		html.EscapeString(secret.Username),
		html.EscapeString(secret.Secret),
	)
}

func cleanupMessage(b *tb.Bot, m *tb.Message, cleanupTime int) {
	time.Sleep(time.Second * time.Duration(cleanupTime))

	if err := b.Delete(m); err != nil {
		log.Error("Unable to delete a message to telegram: "+err.Error(), "chat_id", m.Chat.ID)
	}
}
