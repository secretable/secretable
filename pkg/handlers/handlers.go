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
	"fmt"
	"html"
	"math/rand"
	"secretable/pkg/config"
	"secretable/pkg/crypto"
	"secretable/pkg/localizator"
	"secretable/pkg/log"
	"secretable/pkg/tables"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mr-tron/base58/base58"
	tb "gopkg.in/tucnak/telebot.v2"
)

const (
	genchars = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"0123456789" +
		` !"#$%&'()*+,-./:;<=>?@[\]^_{|}~` + "`"
)

type Handler struct {
	encMode bool

	mastePass string

	cleanupTime  int
	setstates    sync.Map
	waitmpstates sync.Map
	b            *tb.Bot
	tp           *tables.TablesProvider
	locales      *localizator.Localizator
	conf         *config.Config
	confPath     string
}

func NewHandler(b *tb.Bot, tp *tables.TablesProvider, locales *localizator.Localizator, conf *config.Config, confPath string, enc bool) *Handler {
	return &Handler{
		b: b, tp: tp, locales: locales, encMode: enc,
		conf: conf, confPath: confPath,
	}
}

func (h *Handler) Delete(m *tb.Message) {
	index, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(m.Text, "/delete")))
	if err != nil {
		sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "delete_resp_wrong_index"))
		return
	}

	if h.encMode {
		err = h.tp.DeletEncrypted(index - 1)
	} else {
		err = h.tp.DeletSecrets(index - 1)
	}

	if err != nil {
		sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "delete_unable_delete"))
		return
	}

	sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "delete_secret_deleted"))

}

func (h *Handler) Generate(m *tb.Message) {
	lengthStr := strings.TrimSpace(strings.TrimPrefix(m.Text, "/generate"))

	lengthInt, _ := strconv.Atoi(lengthStr)
	if lengthInt <= 0 || lengthInt > 128 {
		lengthInt = 16
	}

	rand.Seed(time.Now().UnixNano())

	chars := []rune(genchars)
	var bld strings.Builder
	for i := 0; i < lengthInt; i++ {
		bld.WriteRune(chars[rand.Intn(len(chars))])
	}
	sendMessage(m, h.b, fmt.Sprintf("<code>%v</code>", html.EscapeString(bld.String())))
}

func (h *Handler) ID(m *tb.Message) {
	sendMessage(m, h.b, fmt.Sprintf("<code>%v</code>", m.Chat.ID))
}

func (h *Handler) Query(m *tb.Message) {
	if h.encMode {
		h.queryEncrypted(m)
	} else {
		h.query(m)
	}
}

func (h *Handler) query(m *tb.Message) {
	rows := h.tp.GetSecrets()
	q := strings.ToLower(m.Text)

	ok := false
	for i, row := range rows {
		if len(row) != 3 {
			continue
		}

		for _, v := range row[:2] {
			if strings.Contains(strings.ToLower(v), q) {
				ok = true
				sendMessage(m, h.b, makeQueryResponse(i, row))
				break
			}
		}
	}

	if !ok {
		sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "query_no_secrets"))
	}
}

func (h *Handler) queryEncrypted(m *tb.Message) {
	privkey, err := getPrivkey(h.b, h.tp, m, h.conf.Salt, h.mastePass)
	if err != nil {
		return
	}

	rows := h.tp.GetEncrypted()

	q := strings.ToLower(m.Text)

	ok := false
	for i, row := range rows {
		if len(row) != 3 {
			continue
		}

		for _, v := range row[:1] {
			if strings.Contains(strings.ToLower(v), q) {
				username, _ := base58.Decode(row[1])
				password, _ := base58.Decode(row[2])

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

				row[1] = string(decUsername)
				row[2] = string(decPassword)

				ok = true
				sendMessage(m, h.b, makeQueryResponse(i+1, row))
				break
			}
		}

	}

	if !ok {
		sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "query_no_secrets"))
	}
}

func (h *Handler) ResetPass(m *tb.Message) {
	if !h.encMode {
		return
	}

	data := strings.TrimSpace(strings.TrimPrefix(m.Text, "/setpass"))

	if data == "" {
		sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "setpass_empty_pass"))
		return
	}

	privkeyBytes, ok, err := getPrivkeyAsBytes(h.b, h.tp, m, h.conf.Salt, h.mastePass)
	if err != nil || !ok {
		sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "setpass_unable_set"))
		return
	}

	b, _ := crypto.MakeRandom(16)
	oldSalt := h.conf.Salt
	h.conf.Salt = base58.Encode(b)
	err = config.UpdateFile(h.confPath, h.conf)
	if err != nil {
		h.conf.Salt = oldSalt
		log.Error("Update config: " + err.Error())
		sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "setpass_unable_set"))
		return
	}

	nonce, _ := crypto.MakeRandom(crypto.NonceSize)
	cypher, err := crypto.EncryptWithPhrase([]byte(data), []byte(h.conf.Salt), nonce, privkeyBytes)
	if err != nil {
		log.Error("Encrypt with password: " + err.Error())
		sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "setpass_unable_set"))
		return
	}

	cypher = append(nonce, cypher...)

	if err = h.tp.SetKey(base58.Encode(cypher)); err != nil {
		log.Error("Store encrypted key to table: " + err.Error())
		sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "setpass_unable_set"))
		return
	}

	h.mastePass = data
	sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "setpasspass_setted"))
}

func (h *Handler) Set(m *tb.Message) {
	sendMessage(m, h.b, h.locales.Get(m.Sender.LanguageCode, "add_resp_command"))
	h.setstates.Store(m.Chat.ID, true)
}

func (h *Handler) MakeStart(infoMsg string) func(m *tb.Message) {
	return func(m *tb.Message) {
		sendMessageWithoutCleanup(m, h.b, infoMsg)
	}
}
