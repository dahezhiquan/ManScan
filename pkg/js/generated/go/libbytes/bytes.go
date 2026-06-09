package bytes

import (
	lib_bytes "ManScan/pkg/js/libs/bytes"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/bytes")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewBuffer": lib_bytes.NewBuffer,

			// Var and consts

			// Objects / Classes
			"Buffer": lib_bytes.NewBuffer,
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
