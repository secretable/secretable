package localizator

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"secretable/pkg/log"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

type Localizator struct {
	locales []string
	m       sync.Map
}

func (l *Localizator) InitFromFS(filesystem fs.FS, basePath string) error {
	files, err := fs.ReadDir(filesystem, basePath)
	if err != nil {
		return errors.Wrap(err, "read directory")
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		target := filepath.Join(basePath, file.Name())

		body, err := fs.ReadFile(filesystem, target)
		if err != nil {
			log.Error("Read file " + target + " :" + err.Error())

			continue
		}

		mkv := make(map[string]string)

		err = json.Unmarshal(body, &mkv)
		if err != nil {
			log.Error("Parse JSON " + target + " :" + err.Error())

			continue
		}

		shortlocale := strings.TrimSuffix(file.Name(), ".json")

		l.locales = append(l.locales, shortlocale)
		for k, v := range mkv {
			l.m.Store(shortlocale+"."+k, v)
		}
	}

	return nil
}

func (l *Localizator) GetLocales() []string {
	a := make([]string, len(l.locales))
	copy(a, l.locales)

	return a
}

func (l *Localizator) Get(locale string, key string) string {
	value, exists := l.m.Load(locale + "." + key)
	if !exists {
		if locale != "en" {
			locale = "en"
			value, exists = l.m.Load(locale + "." + key)
		}

		if !exists {
			return ""
		}
	}

	return value.(string)
}
