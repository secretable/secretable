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

package main

import (
	"fmt"
	"os"
	"time"

	"secretable/pkg/crypto"
	"secretable/pkg/handlers"
	"secretable/pkg/log"
	"secretable/pkg/tables"

	tb "gopkg.in/tucnak/telebot.v2"

	"github.com/jessevdk/go-flags"
	"github.com/mr-tron/base58/base58"
)

const (
	longPollerTimeout = 5 // in sec
)

var opts struct {
	TGToken           string `short:"t" long:"tg_bot_token" description:"Telegram bot token" required:"true"`
	GoogleCredentials string `short:"g" long:"google_credentials" description:"Path to Google credentials JSON file" required:"true"`
	SpreadsheetID     string `short:"s" long:"spreadsheet_id" description:"Spreadsheet ID" required:"true"`
	CleanupTime       int    `short:"c" long:"cleanup_timeout" default:"30" description:"Received and send messages cleanup timeout in seconds"`
	Unencrypted       bool   `short:"u" long:"unencrypted" description:"Unencrypted mode"`
	Salt              string `long:"salt" env:"ST_SALT" description:"Salt for encryption with a master password. Automatically set to environment variable. If not specified, a new one is generated and setted."`
}

var cmds = []tb.Command{
	{
		Text: "/id", Description: "Get your chat id",
	},
	{
		Text: "/generate", Description: "Generate a strong password as recommended by OWASP. You can pass the length of the password like: /generate 8",
	},
	{
		Text: "/add", Description: "Add a new secret",
	},
	{
		Text: "/delete", Description: "Delete secret by index, for example: /delete 12",
	},
	{
		Text: "/setpass", Description: "Set new master password, for example: /setpass your_new_master_pass",
	},
}

func main() {
	_, err := flags.Parse(&opts)
	if flags.WroteHelp(err) {
		return
	}
	if err != nil {
		log.Fatal(err.Error())
		return
	}

	log.Info("⏳ Initialization Secretable")
	log.Info("📝 Google credentials: " + opts.GoogleCredentials)
	log.Info("📄 Spreadsheet ID: " + opts.SpreadsheetID)
	log.Info("🧹 Cleanup timeout: " + fmt.Sprint(opts.CleanupTime, " sec"))
	if opts.Unencrypted {
		log.Info("🔓 Unecrypted mode")
	} else {
		log.Info("🔐 Encrypted mode")

		if opts.Salt == "" {
			log.Info("🧂 Salt not set and will be generated automatically.")
		} else {
			log.Info("🧂 Salt setted")
		}
	}

	tableProvider, err := tables.NewTablesProvider(opts.GoogleCredentials, opts.SpreadsheetID)
	if err != nil {
		log.Fatal("Unable to create tables provider: " + err.Error())
	}

	if !opts.Unencrypted {
		if opts.Salt == "" {
			s, _ := crypto.MakeRandom(32)
			opts.Salt = base58.Encode(s)
			os.Setenv("ST_SALT", opts.Salt)
		}

	}

	b, err := tb.NewBot(tb.Settings{
		Token:  opts.TGToken,
		Poller: &tb.LongPoller{Timeout: longPollerTimeout * time.Second},
	})

	if err != nil {
		log.Fatal("Unable to create new bot instance: " + err.Error())
	}

	handler := handlers.NewHandler(b, tableProvider, opts.CleanupTime, !opts.Unencrypted)

	startMessage := "Welcome! Just enter text into the chat to find secrets or use the commands:\n\n"
	for _, cmd := range cmds {
		startMessage += fmt.Sprintf("<code>%s</code> - %s\n", cmd.Text, cmd.Description)
	}

	b.Handle("/start", middleware(false, false, false, 0, handler, handler.MakeStart(startMessage)))

	b.Handle("/id", middleware(false, false, false, opts.CleanupTime, handler, handler.ID))
	b.Handle("/generate", middleware(false, false, false, opts.CleanupTime, handler, handler.Generate))

	b.Handle("/add", middleware(true, false, true, opts.CleanupTime, handler, handler.Set))
	b.Handle("/setpass", middleware(true, false, true, opts.CleanupTime, handler, handler.ResetPass))
	b.Handle("/delete", middleware(true, false, true, opts.CleanupTime, handler, handler.Delete))
	b.Handle(tb.OnText, middleware(true, true, true, opts.CleanupTime, handler, handler.Query))

	if err = b.SetCommands(cmds); err != nil {
		log.Error("Error of setting commands: " + err.Error())
	}

	log.Info("🚀 Start Telegram Bot")

	b.Start()
}

func middleware(useMasterPassCheck, isQuery, hasAccessControl bool, cleanupTime int, handler *handlers.Handler, next func(*tb.Message)) func(*tb.Message) {
	next = handler.ControlSetSecretMiddleware(isQuery, next)
	next = handler.ControlMasterPassMiddleware(useMasterPassCheck, isQuery, next)
	if hasAccessControl {
		next = handler.AccessMiddleware(next)
	}
	if cleanupTime > 0 {
		next = handler.CleanupMessagesMiddleware(cleanupTime, next)
	}
	next = handler.LoggerMiddleware(next)

	return next
}
