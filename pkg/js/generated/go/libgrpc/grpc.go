package grpc

import (
	lib_grpc "ManScan/pkg/js/libs/grpc"

	"ManScan/pkg/js/gojs"
	"github.com/projectdiscovery/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/grpc")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewClient": lib_grpc.NewClient,

			// Var and consts

			// Objects / Classes
			"Client":  lib_grpc.NewClient,
			"Options": gojs.GetClassConstructor[lib_grpc.Options](&lib_grpc.Options{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
