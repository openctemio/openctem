package password

import (
	_ "embed"
	"errors"
	"strings"
	"sync"
)

// common.txt is the Pwdb top-100000 list from SecLists (MIT license), lower
// cased, printable ASCII, 8 to 64 characters (shorter entries fail the length
// rule anyway). It is embedded so the check never makes a network call.
//
//go:embed common.txt
var commonList string

// ErrPasswordCommon is returned for a password on the list of the most used
// (breached) passwords.
var ErrPasswordCommon = errors.New("password is too common; choose one that is not on lists of breached passwords")

var (
	commonOnce sync.Once
	common     map[string]struct{}
)

// IsCommon reports whether password (case-insensitive) is on the embedded
// list of the most used breached passwords.
func IsCommon(password string) bool {
	commonOnce.Do(func() {
		common = make(map[string]struct{}, strings.Count(commonList, "\n")+1)
		for _, line := range strings.Split(commonList, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				common[line] = struct{}{}
			}
		}
	})
	_, ok := common[strings.ToLower(password)]
	return ok
}
