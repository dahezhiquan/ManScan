package scmr

import (
	lib_scmr "ManScan/pkg/js/libs/scmr"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/scmr")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewClient": lib_scmr.NewClient,

			// Var and consts
			"Auth": lib_scmr.Auth,

			// Objects / Classes
			"Client": lib_scmr.NewClient,
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
