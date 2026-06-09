package vnc

import (
	lib_vnc "ManScan/pkg/js/libs/vnc"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/vnc")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"IsVNC": lib_vnc.IsVNC,

			// Var and consts

			// Objects / Classes
			"IsVNCResponse": gojs.GetClassConstructor[lib_vnc.IsVNCResponse](&lib_vnc.IsVNCResponse{}),
			"VNCClient":     gojs.GetClassConstructor[lib_vnc.VNCClient](&lib_vnc.VNCClient{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
