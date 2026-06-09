package tsch

import (
	lib_tsch "ManScan/pkg/js/libs/tsch"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/tsch")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewClient": lib_tsch.NewClient,

			// Var and consts
			"Auth": lib_tsch.Auth,

			// Objects / Classes
			"Client": lib_tsch.NewClient,
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
