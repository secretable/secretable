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

package tables

import (
	"context"
	"secretable/pkg/log"
	"strings"
	"sync"
	"time"

	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"
)

const (
	encryptedRange = "Encrypted!A1:E"
	secretsRange   = "Secrets!A1:C"
	keysRange      = "Keys!A1:E"

	secretsTitle   = "Secrets"
	encryptedTitle = "Encrypted"
	accessTitle    = "Access"
	keysTitle      = "Keys"

	updateTimeout = 10 // in sec
)

type TablesProvider struct {
	service       *sheets.Service
	spreadsheetId string

	secretsID   int64
	encryptedID int64
	accessID    int64
	keysID      int64

	secrets   [][]string
	encrypted [][]string
	access    []string
	keys      []string

	mx sync.RWMutex
}

func NewTablesProvider(googleCredsFile, spreadsheetId string) (*TablesProvider, error) {
	service, err := sheets.NewService(context.Background(), option.WithCredentialsFile(googleCredsFile))
	if err != nil {
		return nil, err
	}

	tp := new(TablesProvider)
	tp.service = service
	tp.spreadsheetId = spreadsheetId

	for _, tab := range []string{secretsTitle, encryptedTitle, accessTitle, keysTitle} {
		err = createTable(service, spreadsheetId, tab)
		if err != nil {
			return nil, err
		}
	}

	if err = tp.update(); err != nil {
		return nil, err
	}

	go func() {
		for {
			time.Sleep(time.Second * updateTimeout)
			if err = tp.update(); err != nil {
				log.Error("Unable update tables: " + err.Error())
			}
		}
	}()

	return tp, nil
}

func createTable(service *sheets.Service, spreadsheetId, tableTitle string) (err error) {
	_, err = service.Spreadsheets.BatchUpdate(spreadsheetId, &sheets.BatchUpdateSpreadsheetRequest{
		Requests: []*sheets.Request{
			{
				AddSheet: &sheets.AddSheetRequest{
					Properties: &sheets.SheetProperties{
						Title: tableTitle,
					},
				},
			},
		},
	}).Do()

	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}

	return nil
}

func (t *TablesProvider) AppendSecrets(arr []string) error {
	return t.append(secretsRange, arr)
}

func (t *TablesProvider) AppendEncrypted(arr []string) error {
	return t.append(encryptedRange, arr)
}

func (t *TablesProvider) append(sheetRange string, arr []string) error {
	var row []interface{}

	for _, v := range arr {
		row = append(row, v)
	}

	_, err := t.service.Spreadsheets.Values.Append(t.spreadsheetId, sheetRange, &sheets.ValueRange{
		Values: [][]interface{}{
			row,
		},
		MajorDimension: "ROWS",
	}).ValueInputOption("RAW").InsertDataOption("INSERT_ROWS").Do()
	if err != nil {
		log.Error("Unable to append new values to table: "+err.Error(), "spreadsheet_id", t.spreadsheetId, "sheet_range", sheetRange)
	}

	return err
}

func (t *TablesProvider) SetKey(key string) error {
	_, err := t.service.Spreadsheets.Values.Update(t.spreadsheetId, keysRange, &sheets.ValueRange{
		Values: [][]interface{}{
			{
				key,
			},
		},
		MajorDimension: "ROWS",
	}).ValueInputOption("RAW").Do()
	if err != nil {
		log.Error("Unable to append new values to table: "+err.Error(), "spreadsheet_id", t.spreadsheetId, "sheet_range", keysRange)
	}

	return err
}

func (t *TablesProvider) DeletSecrets(index int) error {
	return t.delete(t.secretsID, index)
}

func (t *TablesProvider) DeletEncrypted(index int) error {
	return t.delete(t.encryptedID, index)
}

func (t *TablesProvider) delete(sheetID int64, index int) error {
	_, err := t.service.Spreadsheets.BatchUpdate(t.spreadsheetId, &sheets.BatchUpdateSpreadsheetRequest{
		Requests: []*sheets.Request{
			{
				DeleteDimension: &sheets.DeleteDimensionRequest{
					Range: &sheets.DimensionRange{
						Dimension:  "ROWS",
						StartIndex: int64(index),
						EndIndex:   int64(index + 1),
						SheetId:    sheetID,
					},
				},
			},
		},
	}).Do()
	if err != nil {
		log.Error("Unable to delete values to table: "+err.Error(), "spreadsheet_id", t.spreadsheetId, "index", index)
	}

	return err
}

func (t *TablesProvider) updateSecrets(data []*sheets.GridData) error {
	var newrows [][]string

	for _, item := range data {
		for _, row := range item.RowData {
			var newrowsItem []string

			for _, cell := range row.Values {
				newrowsItem = append(newrowsItem, cell.FormattedValue)
			}

			newrows = append(newrows, newrowsItem)
		}
	}

	t.setSecrets(newrows)
	return nil
}

func (t *TablesProvider) updateEncrypted(data []*sheets.GridData) error {
	var newrows [][]string

	for _, item := range data {
		for _, row := range item.RowData {
			var newrowsItem []string
			for _, cell := range row.Values {
				newrowsItem = append(newrowsItem, cell.FormattedValue)
			}
			newrows = append(newrows, newrowsItem)
		}
	}

	t.setEncrypted(newrows)

	return nil
}

func (t *TablesProvider) updateAccess(data []*sheets.GridData) error {
	var newrows []string

	for _, item := range data {
		for _, row := range item.RowData {
			for _, cell := range row.Values {
				newrows = append(newrows, cell.FormattedValue)
				break
			}
		}
	}
	t.setAccess(newrows)

	return nil
}

func (t *TablesProvider) updateKeys(data []*sheets.GridData) error {
	var newrows []string

	for _, item := range data {
		for _, row := range item.RowData {
			for _, cell := range row.Values {
				newrows = append(newrows, cell.FormattedValue)
				break
			}
		}
	}

	t.setKeys(newrows)

	return nil
}

func (t *TablesProvider) update() error {
	ss, err := t.service.Spreadsheets.Get(t.spreadsheetId).IncludeGridData(true).Do()
	if err != nil {
		return err
	}

	for _, sheet := range ss.Sheets {
		switch sheet.Properties.Title {
		case secretsTitle:
			t.secretsID = sheet.Properties.SheetId
			err = t.updateSecrets(sheet.Data)
		case encryptedTitle:
			t.encryptedID = sheet.Properties.SheetId
			err = t.updateEncrypted(sheet.Data)
		case accessTitle:
			t.accessID = sheet.Properties.SheetId
			err = t.updateAccess(sheet.Data)
		case keysTitle:
			t.keysID = sheet.Properties.SheetId
			err = t.updateKeys(sheet.Data)
		}

		if err != nil {
			return err
		}
	}
	return nil
}

func (s *TablesProvider) setSecrets(rows [][]string) {
	s.mx.Lock()
	s.secrets = make([][]string, len(rows))
	copy(s.secrets, rows)
	s.mx.Unlock()
}

func (s *TablesProvider) setEncrypted(rows [][]string) {
	s.mx.Lock()
	s.encrypted = make([][]string, len(rows))
	copy(s.encrypted, rows)
	s.mx.Unlock()
}

func (s *TablesProvider) GetSecrets() (rows [][]string) {
	s.mx.RLock()
	rows = make([][]string, len(s.secrets))
	copy(rows, s.secrets)
	s.mx.RUnlock()
	return rows
}

func (s *TablesProvider) GetEncrypted() (rows [][]string) {
	s.mx.RLock()
	rows = make([][]string, len(s.encrypted))
	copy(rows, s.encrypted)
	s.mx.RUnlock()
	return rows
}

func (s *TablesProvider) setAccess(rows []string) {
	s.mx.Lock()
	s.access = make([]string, len(rows))
	copy(s.access, rows)
	s.mx.Unlock()
}

func (s *TablesProvider) GetAccess() (rows []string) {
	s.mx.RLock()
	rows = make([]string, len(s.access))
	copy(rows, s.access)
	s.mx.RUnlock()
	return rows
}

func (s *TablesProvider) setKeys(rows []string) {
	s.mx.Lock()
	s.keys = make([]string, len(rows))
	copy(s.keys, rows)
	s.mx.Unlock()
}

func (s *TablesProvider) GetKeys() (rows []string) {
	s.mx.RLock()
	rows = make([]string, len(s.keys))
	copy(rows, s.keys)
	s.mx.RUnlock()
	return rows
}
