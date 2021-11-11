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
	secretesRange = "Secrets!A1:E"
	keysRange     = "Keys!A1:E"
	secretsTitle  = "Secrets"
	keysTitle     = "Keys"

	updateTimeout = 10 // in sec
)

type TablesProvider struct {
	service       *sheets.Service
	spreadsheetID string

	secretsID int64
	keysID    int64
	secrets   [][]string
	keys      []string

	mx sync.RWMutex
}

func NewTablesProvider(googleCredsFile, spreadsheetID string) (*TablesProvider, error) {
	service, err := sheets.NewService(context.Background(), option.WithCredentialsFile(googleCredsFile))
	if err != nil {
		return nil, errors.Wrap(err, "init sheets service")
	}

	tableProvider := new(TablesProvider)
	tableProvider.service = service
	tableProvider.spreadsheetID = spreadsheetID

	for _, tab := range []string{secretsTitle, keysTitle} {
		err = createTable(service, spreadsheetID, tab)
		if err != nil {
			return nil, err
		}
	}

	if err = tableProvider.update(); err != nil {
		return nil, err
	}

	go func() {
		for {
			time.Sleep(time.Second * updateTimeout)

			if err = tableProvider.update(); err != nil {
				log.Error("Unable update tables: " + err.Error())
			}
		}
	}()

	return tableProvider, nil
}

func createTable(service *sheets.Service, spreadsheetID, tableTitle string) (err error) {
	_, err = service.Spreadsheets.BatchUpdate(spreadsheetID, &sheets.BatchUpdateSpreadsheetRequest{
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

func (t *TablesProvider) AddSecrets(arr []string) error {
	row := make([]interface{}, 0)

	for _, v := range arr {
		row = append(row, v)
	}

	_, err := t.service.Spreadsheets.Values.Append(t.spreadsheetID, secretesRange, &sheets.ValueRange{
		Values: [][]interface{}{
			row,
		},
		MajorDimension: "ROWS",
	}).ValueInputOption("RAW").InsertDataOption("INSERT_ROWS").Do()
	if err != nil {
		log.Error("Unable to append new values to table: "+err.Error(),
			"spreadsheet_id", t.spreadsheetID,
			"sheet_range", secretesRange,
		)

		return errors.Wrap(err, "append secrets to table")
	}

	return nil
}

func (t *TablesProvider) SetKey(key string) error {
	_, err := t.service.Spreadsheets.Values.Update(t.spreadsheetID, keysRange, &sheets.ValueRange{
		Values: [][]interface{}{
			{
				key,
			},
		},
		MajorDimension: "ROWS",
	}).ValueInputOption("RAW").Do()
	if err != nil {
		log.Error("Unable to append new values to table: "+err.Error(),
			"spreadsheet_id", t.spreadsheetID,
			"sheet_range", keysRange,
		)

		return errors.Wrap(err, "append key to table")
	}

	return nil
}

func (t *TablesProvider) DeletSecrets(index int) error {
	return t.delete(t.secretsID, index)
}

func (t *TablesProvider) delete(sheetID int64, index int) error {
	_, err := t.service.Spreadsheets.BatchUpdate(t.spreadsheetID, &sheets.BatchUpdateSpreadsheetRequest{
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
		log.Error("Unable to delete values to table: "+err.Error(), "spreadsheet_id", t.spreadsheetID, "index", index)

		return errors.Wrap(err, "delete from table")
	}

	return nil
}

func (t *TablesProvider) updateSecrets(data []*sheets.GridData) {
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
	ss, err := t.service.Spreadsheets.Get(t.spreadsheetID).IncludeGridData(true).Do()
	if err != nil {
		return errors.Wrap(err, "get spreadsheet")
	}

	for _, sheet := range ss.Sheets {
		switch sheet.Properties.Title {
		case secretsTitle:
			t.secretsID = sheet.Properties.SheetId
			t.updateSecrets(sheet.Data)
		case keysTitle:
			t.keysID = sheet.Properties.SheetId
			t.updateKeys(sheet.Data)
		}
	}

	return nil
}

func (t *TablesProvider) setSecrets(rows [][]string) {
	t.mx.Lock()
	t.secrets = make([][]string, len(rows))
	copy(t.secrets, rows)
	t.mx.Unlock()
}

func (t *TablesProvider) GetSecrets() (rows [][]string) {
	t.mx.RLock()
	rows = make([][]string, len(t.secrets))
	copy(rows, t.secrets)
	t.mx.RUnlock()

	return rows
}

func (t *TablesProvider) setKeys(rows []string) {
	t.mx.Lock()
	t.keys = make([]string, len(rows))
	copy(t.keys, rows)
	t.mx.Unlock()
}

func (t *TablesProvider) GetKeys() (rows []string) {
	t.mx.RLock()
	rows = make([]string, len(t.keys))
	copy(rows, t.keys)
	t.mx.RUnlock()

	return rows
}
