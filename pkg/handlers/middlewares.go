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
	"crypto/x509"
	"os"
	"secretable/pkg/crypto"
	"secretable/pkg/log"
	"secretable/pkg/tables"
	"strings"

	"github.com/mr-tron/base58/base58"
	tb "gopkg.in/tucnak/telebot.v2"
)

func (h *Handler) CleanupMessagesMiddleware(cleanupTime int, next func(m *tb.Message)) func(m *tb.Message) {
	return func(m *tb.Message) {
		go cleanupMessage(h.b, m, cleanupTime)
		next(m)
	}
}

func (h *Handler) AccessMiddleware(next func(m *tb.Message)) func(m *tb.Message) {
	return func(m *tb.Message) {
		if !hasAccess(h.b, h.tp, m) {
			return
		}
		next(m)
	}
}

func (h *Handler) ControlMasterPassMiddleware(use bool, isSetHandler bool, next func(m *tb.Message)) func(m *tb.Message) {
	return func(m *tb.Message) {
		if !h.encMode || h.mastePass != "" {
			next(m)
			return
		}

		_, ok := h.waitmpstates.Load(m.Chat.ID)
		h.waitmpstates.Delete(m.Chat.ID)
		if !use {
			next(m)
			return
		}

		if !isSetHandler || isSetHandler && !ok {
			h.waitmpstates.Store(m.Chat.ID, true)
			sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "checkpass_please_enter_pass"))
			return
		}

		h.setPass(m)
	}
}

func (h *Handler) setPass(m *tb.Message) {
	if !hasAccess(h.b, h.tp, m) {
		return
	}

	newMasterPass := strings.TrimSpace(m.Text)

	_, ok, err := getPrivkeyAsBytes(h.b, h.tp, m, newMasterPass)
	if err != nil {
		log.Error("Get private key: " + err.Error())
		sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "setpass_unable_set"))
		return
	}

	if !ok {
		log.Info("🎲 Generating new private key")
		privkey, _ := crypto.GeneratePrivKey()
		binPrivkey, _ := x509.MarshalPKCS8PrivateKey(privkey)
		nonce, _ := crypto.MakeRandom(crypto.NonceSize)
		cypher, err := crypto.EncryptWithPhrase([]byte(newMasterPass), []byte(os.Getenv("ST_SALT")), nonce, binPrivkey)
		if err != nil {
			log.Error("Encrypt with phrase: " + err.Error())
			sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "setpass_unable_set"))
			return
		}

		cypher = append(nonce, cypher...)

		err = h.tp.SetKey(base58.Encode(cypher))
		if err != nil {
			log.Error("Store to table: " + err.Error())
			sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "setpass_unable_set"))
			return
		}
	}

	h.mastePass = newMasterPass

	sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "setpass_pass_changed"))
}

func (h *Handler) ControlSetSecretMiddleware(isSetHandler bool, next func(m *tb.Message)) func(m *tb.Message) {
	return func(m *tb.Message) {
		_, ok := h.setstates.Load(m.Chat.ID)
		h.setstates.Delete(m.Chat.ID)

		if isSetHandler && ok {
			if h.encMode {
				h.querySetNewEncryptedSecret(h.b, h.tp, m, h.mastePass)
			} else {
				h.querySetNewSecret(h.b, h.tp, m)
			}
			return
		}

		next(m)
	}
}
func (h *Handler) LoggerMiddleware(next func(m *tb.Message)) func(m *tb.Message) {
	return func(m *tb.Message) {
		log.Info("📩 Message received: "+m.Text, "chat_id", m.Chat.ID, "fullname", m.Chat.FirstName+" "+m.Chat.LastName, "username", "@"+m.Chat.Username)
		next(m)
	}
}

func (h *Handler) querySetNewSecret(b *tb.Bot, tp *tables.TablesProvider, m *tb.Message) {
	arr := strings.Split(m.Text, "\n")

	if len(arr) < 3 {
		sendMessage(m, b, "Need 3 lines:\nDescription\nUser\nSecret\n\nTry repeat /set")
		return
	}
	arr = arr[:3]

	err := tp.AppendSecrets(arr)

	if err != nil {
		sendMessage(m, b, "Error of appending new encrypted")
		return
	}

	sendMessage(m, b, "New secret appened")
}

func (h *Handler) querySetNewEncryptedSecret(b *tb.Bot, tp *tables.TablesProvider, m *tb.Message, masterPass string) {
	arr := strings.Split(m.Text, "\n")

	if len(arr) < 3 {
		sendMessage(m, b, "Need 3 lines:\nDescription\nUser\nSecret\n\nTry repeat /set")
		return
	}
	arr = arr[:3]

	privkey, err := getPrivkey(b, tp, m, masterPass)
	if err != nil {
		return
	}

	cypher1, _ := crypto.EncryptWithPub(&privkey.PublicKey, []byte(arr[1]))
	cypher2, _ := crypto.EncryptWithPub(&privkey.PublicKey, []byte(arr[2]))

	arr[1] = base58.Encode(cypher1)
	arr[2] = base58.Encode(cypher2)

	err = tp.AppendEncrypted(arr)

	if err != nil {
		sendMessage(m, b, "Error of appending new encrypted")
		return
	}

	sendMessage(m, b, "New secret appened")
}
