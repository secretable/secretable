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
	"secretable/pkg/crypto"
	"secretable/pkg/log"
	"strings"

	"github.com/mr-tron/base58/base58"
	tb "gopkg.in/tucnak/telebot.v2"
)

func (h *Handler) CleanupMessagesMiddleware(cleanupTime int, next func(m *tb.Message)) func(m *tb.Message) {
	return func(m *tb.Message) {
		go cleanupMessage(h.Bot, m, cleanupTime)
		next(m)
	}
}

func (h *Handler) AccessMiddleware(next func(m *tb.Message)) func(m *tb.Message) {
	return func(m *tb.Message) {
		if !h.hasAccess(m) {
			return
		}

		next(m)
	}
}

func (h *Handler) ControlMasterPassMiddleware(
	use bool, isSetHandler bool, next func(m *tb.Message),
) func(m *tb.Message) {
	return func(msg *tb.Message) {
		if h.mastePass != "" {
			next(msg)

			return
		}

		_, exists := h.waitmpstates.Load(msg.Chat.ID)
		h.waitmpstates.Delete(msg.Chat.ID)

		if !use {
			next(msg)

			return
		}

		if !isSetHandler || isSetHandler && !exists {
			h.waitmpstates.Store(msg.Chat.ID, true)
			h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "checkpass_please_enter_pass"))

			return
		}

		h.setPass(msg)
	}
}

func (h *Handler) setPass(msg *tb.Message) {
	if !h.hasAccess(msg) {
		return
	}

	newMasterPass := strings.TrimSpace(msg.Text)

	_, exists, err := getPrivkeyAsBytes(h.TablesProvider, h.Config.Salt, newMasterPass)
	if err != nil {
		log.Error("Get private key: " + err.Error())
		h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "setpass_unable_set"))

		return
	}

	if !exists {
		log.Info("🎲 Generating new private key")

		privkey, _ := crypto.GeneratePrivKey()
		binPrivkey, _ := x509.MarshalPKCS8PrivateKey(privkey)
		nonce, _ := crypto.MakeRandom(crypto.NonceSize)

		cypher, err := crypto.EncryptWithPhrase([]byte(newMasterPass), []byte(h.Config.Salt), nonce, binPrivkey)
		if err != nil {
			log.Error("Encrypt with phrase: " + err.Error())
			h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "setpass_unable_set"))

			return
		}

		cypher = append(nonce, cypher...)

		err = h.TablesProvider.SetKey(base58.Encode(cypher))
		if err != nil {
			log.Error("Store to table: " + err.Error())
			h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "setpass_unable_set"))

			return
		}
	}

	h.mastePass = newMasterPass

	h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "setpass_pass_changed"))
}

func (h *Handler) ControlSetSecretMiddleware(isSetHandler bool, next func(m *tb.Message)) func(m *tb.Message) {
	return func(msg *tb.Message) {
		_, ok := h.setstates.Load(msg.Chat.ID)
		h.setstates.Delete(msg.Chat.ID)

		if isSetHandler && ok {
			h.querySetNewSecretsSecret(msg, h.mastePass)

			return
		}

		next(msg)
	}
}
func (h *Handler) LoggerMiddleware(next func(m *tb.Message)) func(m *tb.Message) {
	return func(msg *tb.Message) {
		log.Info("📩 Message received: "+msg.Text,
			"chat_id", msg.Chat.ID,
			"fullname", msg.Chat.FirstName+" "+msg.Chat.LastName,
			"username", "@"+msg.Chat.Username,
		)

		next(msg)
	}
}

func (h *Handler) querySetNewSecretsSecret(msg *tb.Message, masterPass string) {
	arr := strings.Split(msg.Text, "\n")

	if len(arr) < numbQueryColumns {
		h.sendMessage(msg, "Need 3 lines:\nDescription\nUser\nSecret\n\nTry repeat /set")

		return
	}

	arr = arr[:numbQueryColumns]

	privkey, err := getPrivkey(h.TablesProvider, h.Config.Salt, masterPass)
	if err != nil {
		return
	}

	cypher1, _ := crypto.EncryptWithPub(&privkey.PublicKey, []byte(arr[1]))
	cypher2, _ := crypto.EncryptWithPub(&privkey.PublicKey, []byte(arr[2]))

	arr[1] = base58.Encode(cypher1)
	arr[2] = base58.Encode(cypher2)

	err = h.TablesProvider.AddSecrets(arr)

	if err != nil {
		h.sendMessage(msg, "Error of appending new encrypted")

		return
	}

	h.sendMessage(msg, "New secret appened")
}
