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
	"github.com/pkg/errors"
)

const (
	longPollerTimeout = 5 // in sec
	saltLength        = 32
)

//go:embed locales
var localesFS embed.FS

func main() {
	opts, next, err := getFlags()
	if err != nil {
		log.Fatal(err.Error())

		return
	}

	if !next {
		return
	}

	log.Info("⏳ Initialization Secretable")

	locales := new(localizator.Localizator)
	if err = locales.InitFromFS(localesFS, "locales"); err != nil {
		log.Fatal("Initialization locales: " + err.Error())

		return
	}

	log.Info("🌎 Supported locales: " + strings.Join(locales.GetLocales(), ", "))

	conf, err := getConf(opts.ConfigFile)
	if err != nil {
		log.Fatal("Get config: " + err.Error())

		return
	}

	tableProvider, err := tables.NewTablesProvider(conf.GoogleCredentials, conf.SpreadsheetID)
	if err != nil {
		log.Fatal("Unable to create tables provider: " + err.Error())
	}

	bot, err := tb.NewBot(tb.Settings{
		Token: conf.TelegramBotToken,
		Poller: &tb.LongPoller{
			Timeout: longPollerTimeout * time.Second,
		},
	})

	if err != nil {
		log.Fatal("Unable to create new bot instance: " + err.Error())
	}

	setRouting(
		bot,
		&handlers.Handler{
			Bot:            bot,
			TablesProvider: tableProvider,
			Locales:        locales,
			Config:         conf,
		},
		conf,
	)

	log.Info("🚀 Start Telegram Bot")

	bot.Start()
}

type option struct {
	ConfigFile string `short:"c" default:"" long:"config" description:"Path to config file" required:"false"`
}

func getFlags() (opts option, ok bool, err error) {
	_, err = flags.Parse(&opts)
	if flags.WroteHelp(err) {
		return opts, false, nil
	}

	if err != nil {
		return opts, false, errors.Wrap(err, "parse flags")
	}

	if opts.ConfigFile == "" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			return opts, false, errors.Wrap(err, "get home dir")
		}

		opts.ConfigFile = filepath.Join(homedir, ".secretable", "config.yaml")
	}

	return opts, true, nil
}

func getConf(path string) (conf *config.Config, err error) {
	conf, err = config.ParseFromFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "parse config from file")
	}

	log.Info("📝 Google credentials: " + conf.GoogleCredentials)
	log.Info("📄 Spreadsheet ID: " + conf.SpreadsheetID)
	log.Info("🧹 Cleanup timeout: " + fmt.Sprint(conf.CleanupTimeout, " sec"))

	if conf.Salt == "" {
		s, _ := crypto.MakeRandom(saltLength)
		conf.Salt = base58.Encode(s)

		if err = config.UpdateFile(conf); err != nil {
			return nil, errors.Wrap(err, "update config file")
		}

		log.Info("🧂 Salt generated automatically")
	}

	return conf, nil
}

func middleware(
	useMasterPassCheck, isQuery, hasAccessControl bool,
	cleanupTime int, handler *handlers.Handler,
	next func(*tb.Message),
) func(*tb.Message) {
	next = handler.ControlSetSecretMiddleware(isQuery, next)
	next = handler.ControlMasterPassMiddleware(useMasterPassCheck, isQuery, next)

	if hasAccessControl {
		next = handler.AccessMiddleware(next)
	}

	if cleanupTime > 0 {
		next = handler.CleanupMessagesMiddleware(cleanupTime, next)
	}

	return handler.LoggerMiddleware(next)
}

func setRouting(bot *tb.Bot, handler *handlers.Handler, conf *config.Config) {
	var cmds = []tb.Command{
		{
			Text: "/id", Description: "Get your chat id",
		},
		{
			Text: "/generate", Description: "Generate a strong password as recommended by OWASP. " +
				"You can pass the length of the password like: /generate 8",
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

	startMessage := "Welcome! Just enter text into the chat to find secrets or use the commands:\n\n"

	if err := bot.SetCommands(cmds); err != nil {
		log.Error("Error of setting commands: " + err.Error())
	}

	for _, cmd := range cmds {
		startMessage += fmt.Sprintf("<code>%s</code> - %s\n", cmd.Text, cmd.Description)
	}

	bot.Handle("/start", middleware(false, false, false, 0, handler, handler.MakeStart(startMessage)))

	bot.Handle("/id", middleware(false, false, false, conf.CleanupTimeout, handler, handler.ID))
	bot.Handle("/generate", middleware(false, false, false, conf.CleanupTimeout, handler, handler.Generate))

	bot.Handle("/add", middleware(true, false, true, conf.CleanupTimeout, handler, handler.Set))
	bot.Handle("/setpass", middleware(true, false, true, conf.CleanupTimeout, handler, handler.ResetPass))
	bot.Handle("/delete", middleware(true, false, true, conf.CleanupTimeout, handler, handler.Delete))
	bot.Handle(tb.OnText, middleware(true, true, true, conf.CleanupTimeout, handler, handler.Query))
}
