/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                  <aegis.z2h.dev>
 *     .\_/.
 */

package log

import (
	"log"
	"sync"
)

type Level int

const Error Level = 2
const Warn Level = 3
const Info Level = 4
const Debug Level = 5
const Trace Level = 6

var currentLevel = Warn
var mux sync.Mutex

func SetLevel(l Level) {
	mux.Lock()
	defer mux.Unlock()
	if l < 2 || l > 6 {
		return
	}
	currentLevel = l
}

func GetLevel(v ...any) Level {
	mux.Lock()
	defer mux.Unlock()
	return currentLevel
}

func FatalLn(v ...any) {
	log.Fatalln(v...)
}

func ErrorLn(v ...any) {
	l := GetLevel()
	if l > Error {
		return
	}
	log.Println(v...)
}

func WarnLn(v ...any) {
	l := GetLevel()
	if l > Warn {
		return
	}
	log.Println(v...)
}

func InfoLn(v ...any) {
	l := GetLevel()
	if l > Info {
		return
	}
	log.Println(v...)
}

func DebugLn(v ...any) {
	l := GetLevel()
	if l > Debug {
		return
	}
	log.Println(v...)
}

func TraceLn(v ...any) {
	l := GetLevel()
	if l > Trace {
		return
	}
	log.Println(v...)
}
