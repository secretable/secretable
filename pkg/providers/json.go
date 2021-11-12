package providers

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"secretable/pkg/log"
	"sync"

	"github.com/pkg/errors"
)

type jsonStorage struct {
	Secrets []SecretsData `json:"secrets"`
	Key     string        `json:"key"`
}

type JSONStorage struct {
	filepath string
	mx       sync.RWMutex
}

func NewJSONStorage(path string) (*JSONStorage, error) {
	storage := new(JSONStorage)
	storage.filepath = path

	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
				return nil, errors.Wrap(err, "mkdir")
			}

			if file, err = os.Create(path); err != nil {
				return nil, errors.Wrap(err, "create file")
			}

			log.Info("🗄 Created JSON storage file " + path)
		} else {
			return nil, errors.Wrap(err, "open file")
		}
	}

	file.Close()

	return storage, nil
}

func (t *JSONStorage) AddSecret(data SecretsData) error {
	t.mx.Lock()
	defer t.mx.Unlock()

	storage, err := readFile(t.filepath)
	if err != nil {
		return errors.Wrap(err, "read file")
	}

	storage.Secrets = append(storage.Secrets, data)

	if err = writeFile(t.filepath, storage); err != nil {
		return errors.Wrap(err, "write file")
	}

	return nil
}

func readFile(path string) (storage jsonStorage, err error) {
	file, err := os.Open(path)
	if err != nil {
		return storage, errors.Wrap(err, "open file")
	}

	defer file.Close()

	if err = json.NewDecoder(file).Decode(&storage); err != nil && !errors.Is(err, io.EOF) {
		return storage, errors.Wrap(err, "unmarshal json")
	}

	return storage, nil
}

func writeFile(path string, storage jsonStorage) (err error) {
	b, _ := json.Marshal(storage)

	if err = os.WriteFile(path, b, os.ModePerm); err != nil {
		return errors.Wrap(err, "write file")
	}

	return nil
}

func (t *JSONStorage) SetKey(key string) error {
	t.mx.Lock()
	defer t.mx.Unlock()

	storage, err := readFile(t.filepath)
	if err != nil {
		return errors.Wrap(err, "read file")
	}

	storage.Key = key

	if err = writeFile(t.filepath, storage); err != nil {
		return errors.Wrap(err, "write file")
	}

	return nil
}

func (t *JSONStorage) DeleteSecret(index int) error {
	t.mx.Lock()
	defer t.mx.Unlock()

	storage, err := readFile(t.filepath)
	if err != nil {
		return errors.Wrap(err, "read file")
	}

	if index < 0 || index >= len(storage.Secrets) {
		return nil
	}

	storage.Secrets = append(storage.Secrets[:index], storage.Secrets[index+1:]...)

	if err = writeFile(t.filepath, storage); err != nil {
		return errors.Wrap(err, "write file")
	}

	return nil
}

func (t *JSONStorage) GetSecrets() (secrets []SecretsData, err error) {
	storage, err := readFile(t.filepath)
	if err != nil {
		return nil, errors.Wrap(err, "read file")
	}

	return storage.Secrets, nil
}

func (t *JSONStorage) GetKey() (string, error) {
	storage, err := readFile(t.filepath)
	if err != nil {
		return "", errors.Wrap(err, "read file")
	}

	return storage.Key, nil
}
