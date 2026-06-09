package wmi

import (
	lib_wmi "ManScan/pkg/js/libs/wmi"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/wmi")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewClient": lib_wmi.NewClient,

			// Var and consts
			"Auth": lib_wmi.Auth,

			// Objects / Classes
			"Client": lib_wmi.NewClient,
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
