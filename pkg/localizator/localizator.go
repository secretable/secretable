package localizator

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"secretable/pkg/log"
	"strings"
	"sync"
)

type Localizator struct {
	locales []string
	m       sync.Map
}

func (l *Localizator) InitFromFS(f fs.FS, basePath string) error {
	files, err := fs.ReadDir(f, basePath)
	if err != nil {
		return fmt.Errorf("read dir: %s", err.Error())
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		target := filepath.Join(basePath, file.Name())
		b, err := fs.ReadFile(f, target)
		if err != nil {
			log.Error("Read file " + target + " :" + err.Error())
			continue
		}

		m := make(map[string]string)

		err = json.Unmarshal(b, &m)
		if err != nil {
			log.Error("Parse JSON " + target + " :" + err.Error())
			continue
		}

		shortlocale := strings.TrimSuffix(file.Name(), ".json")

		l.locales = append(l.locales, shortlocale)
		for k, v := range m {
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
	v, ok := l.m.Load(locale + "." + key)
	if !ok {
		if locale != "en" {
			locale = "en"
			v, ok = l.m.Load(locale + "." + key)
		}
		if !ok {
			return ""
		}
	}

	return v.(string)
}
