package mssql

import (
	lib_mssql "ManScan/pkg/js/libs/mssql"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/mssql")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Objects / Classes
			"MSSQLClient": gojs.GetClassConstructor[lib_mssql.MSSQLClient](&lib_mssql.MSSQLClient{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
