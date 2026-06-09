package pop3

import (
	lib_pop3 "ManScan/pkg/js/libs/pop3"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/pop3")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"IsPOP3": lib_pop3.IsPOP3,

			// Var and consts

			// Objects / Classes
			"IsPOP3Response": gojs.GetClassConstructor[lib_pop3.IsPOP3Response](&lib_pop3.IsPOP3Response{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
