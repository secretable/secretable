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

	"github.com/pkg/errors"
	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"
)

const (
	encryptedRange = "Encrypted!A1:E"
	keysRange      = "Keys!A1:E"
	encryptedTitle = "Encrypted"
	keysTitle      = "Keys"

	updateTimeout = 10 // in sec
)

type TablesProvider struct {
	service       *sheets.Service
	spreadsheetId string

	encryptedID int64
	keysID      int64
	encrypted   [][]string
	keys        []string

	mx sync.RWMutex
}

func NewTablesProvider(googleCredsFile, spreadsheetId string) (*TablesProvider, error) {
	service, err := sheets.NewService(context.Background(), option.WithCredentialsFile(googleCredsFile))
	if err != nil {
		return nil, errors.Wrap(err, "init sheets service")
	}

	tp := new(TablesProvider)
	tp.service = service
	tp.spreadsheetId = spreadsheetId

	for _, tab := range []string{encryptedTitle, keysTitle} {
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
		return errors.Wrap(err, "add sheet")
	}

	return nil
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
		return errors.Wrap(err, "append secrets to table")
	}

	return nil
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
		return errors.Wrap(err, "append key to table")
	}

	return nil
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
		return errors.Wrap(err, "delete from table")
	}

	return nil
}

func (t *TablesProvider) updateEncrypted(data []*sheets.GridData) {
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
}

func (t *TablesProvider) updateKeys(data []*sheets.GridData) {
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
}

func (t *TablesProvider) update() error {
	ss, err := t.service.Spreadsheets.Get(t.spreadsheetId).IncludeGridData(true).Do()
	if err != nil {
		return errors.Wrap(err, "get spreadsheet")
	}

	for _, sheet := range ss.Sheets {
		switch sheet.Properties.Title {
		case encryptedTitle:
			t.encryptedID = sheet.Properties.SheetId
			t.updateEncrypted(sheet.Data)
		case keysTitle:
			t.keysID = sheet.Properties.SheetId
			t.updateKeys(sheet.Data)
		}
	}
	return nil
}

func (s *TablesProvider) setEncrypted(rows [][]string) {
	s.mx.Lock()
	s.encrypted = make([][]string, len(rows))
	copy(s.encrypted, rows)
	s.mx.Unlock()
}

func (s *TablesProvider) GetEncrypted() (rows [][]string) {
	s.mx.RLock()
	rows = make([][]string, len(s.encrypted))
	copy(rows, s.encrypted)
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
