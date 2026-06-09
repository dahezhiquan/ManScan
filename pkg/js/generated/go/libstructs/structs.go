package structs

import (
	lib_structs "ManScan/pkg/js/libs/structs"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/structs")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"Pack":            lib_structs.Pack,
			"StructsCalcSize": lib_structs.StructsCalcSize,
			"Unpack":          lib_structs.Unpack,

			// Var and consts

			// Objects / Classes

		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
