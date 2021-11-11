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

package log

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	skipFrameCount = 4
)

func Init() {
	cw := zerolog.NewConsoleWriter()
	cw.Out = os.Stderr
	cw.TimeFormat = "02 Jan 06 15:04:05 MST"
	log.Logger = log.Output(cw).With().Caller().CallerWithSkipFrameCount(skipFrameCount).Logger()
}

func Debug(msg string, pairs ...interface{}) {
	printLog(log.Debug(), msg, pairs...)
}

func Info(msg string, pairs ...interface{}) {
	printLog(log.Info(), msg, pairs...)
}

func Error(msg string, pairs ...interface{}) {
	printLog(log.Error(), msg, pairs...)
}

func Panic(msg string, pairs ...interface{}) {
	printLog(log.Panic(), msg, pairs...)
}

func Fatal(msg string, pairs ...interface{}) {
	printLog(log.Fatal(), msg, pairs...)
}

func printLog(event *zerolog.Event, msg string, pairs ...interface{}) {
	k := ""

	for i, kv := range pairs {
		if i%2 == 0 {
			v, ok := kv.(string)
			if ok {
				k = v
			}
		} else {
			event.Interface(k, kv)
		}
	}

	event.Msg(msg)
}
