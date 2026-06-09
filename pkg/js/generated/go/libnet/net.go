package net

import (
	lib_net "ManScan/pkg/js/libs/net"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/net")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"Open":    lib_net.Open,
			"OpenTLS": lib_net.OpenTLS,

			// Var and consts

			// Objects / Classes
			"NetConn": gojs.GetClassConstructor[lib_net.NetConn](&lib_net.NetConn{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
