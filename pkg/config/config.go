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

package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"secretable/pkg/log"

	"gopkg.in/yaml.v3"
)

type Config struct {
	TelegramBotToken  string `yaml:"telegram_bot_token"`
	GoogleCredentials string `yaml:"google_credentials_file"`
	SpreadsheetID     string `yaml:"spreadsheet_id"`
	CleanupTimeout    int    `yaml:"cleanup_timeout"`
	Unencrypted       bool   `yaml:"unencrypted"`
	Salt              string `yaml:"salt"`
}

func ParseFromFile(path string) (config *Config, err error) {
	config = new(Config)
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if file, err = os.Create(path); err != nil {
				return nil, err
			}
			log.Info("📝 Created config file " + path)
		} else {
			return nil, err
		}
	}

	defer file.Close()

	if err = yaml.NewDecoder(file).Decode(config); err != nil && err != io.EOF {
		return nil, err
	}

	return config, nil
}

func UpdateFile(path string, config *Config) error {
	buf := bytes.NewBuffer([]byte{})
	if err := yaml.NewEncoder(buf).Encode(config); err != nil {
		return nil
	}
	return os.WriteFile(path, buf.Bytes(), os.ModePerm)
}