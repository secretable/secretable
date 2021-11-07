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
	"errors"
	"fmt"
	"html"
	"secretable/pkg/crypto"
	"secretable/pkg/log"
	"secretable/pkg/tables"
	"time"

	"github.com/mr-tron/base58/base58"
	tb "gopkg.in/tucnak/telebot.v2"
)

func sendMessage(m *tb.Message, b *tb.Bot, msg string) {
	resp, err := b.Send(m.Chat, msg, tb.Silent, tb.ModeHTML)
	if err != nil {
		log.Error("Unable to send a message to telegram: "+err.Error(), "chat_id", m.Chat.ID, "message", msg)
		return
	}

	go cleanupMessage(b, resp, 10)
}

func sendMessageWithoutCleanup(m *tb.Message, b *tb.Bot, msg string) {
	_, err := b.Send(m.Chat, msg, tb.Silent, tb.ModeHTML)
	if err != nil {
		log.Error("Unable to send a message to telegram"+err.Error(), "chat_id", m.Chat.ID, "message", msg)
		return
	}
}

func hasAccess(b *tb.Bot, tp *tables.TablesProvider, m *tb.Message) bool {
	id := fmt.Sprint(m.Chat.ID)
	for _, a := range tp.GetAccess() {
		if a == id {
			return true
		}
	}

	sendMessage(m, b, "Access forbidden")
	return false
}

func getPrivkeyAsBytes(b *tb.Bot, tp *tables.TablesProvider, m *tb.Message, salt, masterPass string) ([]byte, bool, error) {
	keys := tp.GetKeys()
	if len(keys) == 0 {
		return nil, false, nil
	}

	key, err := base58.Decode(keys[0])
	if err != nil {
		return nil, false, fmt.Errorf("base58 decode: %s", err.Error())
	}
	if len(key) < 12 {
		return nil, false, fmt.Errorf("invalid format")
	}
	nonce := key[:12]
	encprivkey := key[12:]

	decPrivkey, err := crypto.DecryptWithPhrase([]byte(masterPass), []byte(salt), nonce, encprivkey)
	if err != nil {
		return nil, false, fmt.Errorf("decrypt with phrase: %s", err.Error())
	}

	return decPrivkey, true, nil
}

func getPrivkey(b *tb.Bot, tp *tables.TablesProvider, m *tb.Message, salt, masterPass string) (*ecdsa.PrivateKey, error) {
	decPrivkey, ok, err := getPrivkeyAsBytes(b, tp, m, salt, masterPass)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, errors.New("missing private key")
	}

	privkey, err := x509.ParsePKCS8PrivateKey(decPrivkey)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8: %s", err.Error())
	}

	return privkey.(*ecdsa.PrivateKey), nil
}

func makeQueryResponse(index int, row []string) string {
	return fmt.Sprintf("(%d) <b>%s</b>\n<code>%s</code>\n<code>%s</code>",
		index,
		html.EscapeString(row[0]),
		html.EscapeString(row[1]),
		html.EscapeString(row[2]),
	)
}

func cleanupMessage(b *tb.Bot, m *tb.Message, cleanupTime int) {
	time.Sleep(time.Second * time.Duration(cleanupTime))
	if err := b.Delete(m); err != nil {
		log.Error("Unable to delete a message to telegram: "+err.Error(), "chat_id", m.Chat.ID)
	}
}
