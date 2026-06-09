package goconsole

import (
	lib_goconsole "ManScan/pkg/js/libs/goconsole"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/goconsole")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewGoConsolePrinter": lib_goconsole.NewGoConsolePrinter,

			// Var and consts

			// Objects / Classes
			"GoConsolePrinter": gojs.GetClassConstructor[lib_goconsole.GoConsolePrinter](&lib_goconsole.GoConsolePrinter{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
