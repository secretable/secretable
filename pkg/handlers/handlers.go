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
	"crypto/rand"
	"fmt"
	"html"
	"math/big"
	"secretable/pkg/config"
	"secretable/pkg/crypto"
	"secretable/pkg/localizator"
	"secretable/pkg/log"
	"secretable/pkg/tables"
	"strconv"
	"strings"
	"sync"

	"github.com/mr-tron/base58/base58"
	tb "gopkg.in/tucnak/telebot.v2"
)

const (
	numbQueryColumns = 3

	genchars = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"0123456789" +
		` !"#$%&'()*+,-./:;<=>?@[\]^_{|}~` + "`"

	saltLength = 16
)

type Handler struct {
	Bot            *tb.Bot
	TablesProvider *tables.TablesProvider
	Locales        *localizator.Localizator
	Config         *config.Config

	mastePass string
	setstates sync.Map

	waitmpstates sync.Map
}

func (h *Handler) Delete(msg *tb.Message) {
	index, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(msg.Text, "/delete")))
	if err != nil {
		h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "delete_resp_wrong_index"))

		return
	}

	err = h.TablesProvider.DeleteSecrets(index - 1)

	if err != nil {
		h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "delete_unable_delete"))

		return
	}

	h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "delete_secret_deleted"))
}

func (h *Handler) Generate(msg *tb.Message) {
	lengthStr := strings.TrimSpace(strings.TrimPrefix(msg.Text, "/generate"))

	lengthInt, _ := strconv.Atoi(lengthStr)
	if lengthInt <= 0 || lengthInt > 128 {
		lengthInt = 16
	}

	chars := []rune(genchars)

	var bld strings.Builder

	for i := 0; i < lengthInt; i++ {
		nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		bld.WriteRune(chars[int(nBig.Int64())])
	}
	h.sendMessage(msg, fmt.Sprintf("<code>%v</code>", html.EscapeString(bld.String())))
}

func (h *Handler) ID(m *tb.Message) {
	h.sendMessage(m, fmt.Sprintf("<code>%v</code>", m.Chat.ID))
}

func (h *Handler) Query(msg *tb.Message) {
	privkey, err := getPrivkey(h.TablesProvider, h.Config.Salt, h.mastePass)
	if err != nil {
		return
	}

	secrets := h.TablesProvider.GetSecrets()
	query := strings.ToLower(msg.Text)
	exists := false

	for index, secret := range secrets {
		if !strings.Contains(strings.ToLower(secret.Description), query) {
			continue
		}

		username, _ := base58.Decode(secret.Username)
		password, _ := base58.Decode(secret.Secret)

		decUsername, err := crypto.DecryptWithPriv(privkey, username)
		if err != nil {
			log.Error("Decrypt username with private key: " + err.Error())

			break
		}

		decPassword, err := crypto.DecryptWithPriv(privkey, password)
		if err != nil {
			log.Error("Decrypt password with private key: " + err.Error())

			break
		}

		secret.Username = string(decUsername)
		secret.Secret = string(decPassword)

		exists = true

		h.sendMessage(msg, makeQueryResponse(index+1, secret))

		break
	}

	if !exists {
		h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "query_no_secrets"))
	}
}

func (h *Handler) ResetPass(msg *tb.Message) {
	data := strings.TrimSpace(strings.TrimPrefix(msg.Text, "/setpass"))

	if data == "" {
		h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "setpass_empty_pass"))

		return
	}

	privkeyBytes, ok, err := getPrivkeyAsBytes(h.TablesProvider, h.Config.Salt, h.mastePass)
	if err != nil || !ok {
		h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "setpass_unable_set"))

		return
	}

	b, _ := crypto.MakeRandom(saltLength)
	oldSalt := h.Config.Salt
	h.Config.Salt = base58.Encode(b)

	err = config.UpdateFile(h.Config)
	if err != nil {
		log.Error("Update config: " + err.Error())

		h.Config.Salt = oldSalt
		h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "setpass_unable_set"))

		return
	}

	nonce, _ := crypto.MakeRandom(crypto.NonceSize)

	cypher, err := crypto.EncryptWithPhrase([]byte(data), []byte(h.Config.Salt), nonce, privkeyBytes)
	if err != nil {
		log.Error("Encrypt with password: " + err.Error())
		h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "setpass_unable_set"))

		return
	}

	cypher = append(nonce, cypher...)

	if err = h.TablesProvider.SetKey(base58.Encode(cypher)); err != nil {
		log.Error("Store encrypted key to table: " + err.Error())
		h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "setpass_unable_set"))

		return
	}

	h.mastePass = data
	h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "setpasspass_setted"))
}

func (h *Handler) Set(msg *tb.Message) {
	h.sendMessage(msg, h.Locales.Get(msg.Sender.LanguageCode, "add_resp_command"))
	h.setstates.Store(msg.Chat.ID, true)
}

func (h *Handler) MakeStart(infoMsg string) func(m *tb.Message) {
	return func(m *tb.Message) {
		h.sendMessageWithoutCleanup(m, infoMsg)
	}
}
