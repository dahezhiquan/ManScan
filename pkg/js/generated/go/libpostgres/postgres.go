package postgres

import (
	lib_postgres "ManScan/pkg/js/libs/postgres"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/postgres")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Objects / Classes
			"PGClient": gojs.GetClassConstructor[lib_postgres.PGClient](&lib_postgres.PGClient{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
