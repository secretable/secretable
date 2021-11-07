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
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"secretable/pkg/config"
	"secretable/pkg/crypto"
	"secretable/pkg/handlers"
	"secretable/pkg/localizator"
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
	ConfigFile string `short:"c" default:"" long:"config" description:"Path to config file" required:"false"`
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

//go:embed locales
var localesFS embed.FS

func main() {
	_, err := flags.Parse(&opts)
	if flags.WroteHelp(err) {
		return
	}
	if err != nil {
		log.Fatal(err.Error())
		return
	}

	if opts.ConfigFile == "" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err.Error())
			return
		}
		opts.ConfigFile = filepath.Join(homedir, ".secretable", "config.yaml")
	}

	conf, err := config.ParseFromFile(opts.ConfigFile)
	if err != nil {
		log.Fatal(err.Error())
		return
	}

	log.Info("⏳ Initialization Secretable")
	log.Info("📝 Google credentials: " + conf.GoogleCredentials)
	log.Info("📄 Spreadsheet ID: " + conf.SpreadsheetID)
	log.Info("🧹 Cleanup timeout: " + fmt.Sprint(conf.CleanupTimeout, " sec"))

	if conf.Unencrypted {
		log.Info("🔓 Unecrypted mode")
	} else {
		log.Info("🔐 Encrypted mode")

		if conf.Salt == "" {
			log.Info("🧂 Salt not set and will be generated automatically.")
		} else {
			log.Info("🧂 Salt setted")
		}
	}

	locales := new(localizator.Localizator)
	if err = locales.InitFromFS(localesFS, "locales"); err != nil {
		log.Fatal("Initialization locales: " + err.Error())
	}

	log.Info("🌎 Supported locales: " + strings.Join(locales.GetLocales(), ", "))

	tableProvider, err := tables.NewTablesProvider(conf.GoogleCredentials, conf.SpreadsheetID)
	if err != nil {
		log.Fatal("Unable to create tables provider: " + err.Error())
	}

	if !conf.Unencrypted {
		if conf.Salt == "" {
			s, _ := crypto.MakeRandom(32)
			conf.Salt = base58.Encode(s)
		}
	}

	b, err := tb.NewBot(tb.Settings{
		Token:  conf.TelegramBotToken,
		Poller: &tb.LongPoller{Timeout: longPollerTimeout * time.Second},
	})

	if err != nil {
		log.Fatal("Unable to create new bot instance: " + err.Error())
	}

	handler := handlers.NewHandler(b, tableProvider, locales, conf, opts.ConfigFile, !conf.Unencrypted)

	startMessage := "Welcome! Just enter text into the chat to find secrets or use the commands:\n\n"
	for _, cmd := range cmds {
		startMessage += fmt.Sprintf("<code>%s</code> - %s\n", cmd.Text, cmd.Description)
	}

	b.Handle("/start", middleware(false, false, false, 0, handler, handler.MakeStart(startMessage)))

	b.Handle("/id", middleware(false, false, false, conf.CleanupTimeout, handler, handler.ID))
	b.Handle("/generate", middleware(false, false, false, conf.CleanupTimeout, handler, handler.Generate))

	b.Handle("/add", middleware(true, false, true, conf.CleanupTimeout, handler, handler.Set))
	b.Handle("/setpass", middleware(true, false, true, conf.CleanupTimeout, handler, handler.ResetPass))
	b.Handle("/delete", middleware(true, false, true, conf.CleanupTimeout, handler, handler.Delete))
	b.Handle(tb.OnText, middleware(true, true, true, conf.CleanupTimeout, handler, handler.Query))

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
