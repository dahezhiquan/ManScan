package oracle

import (
	lib_oracle "ManScan/pkg/js/libs/oracle"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/oracle")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Objects / Classes
			"IsOracleResponse": gojs.GetClassConstructor[lib_oracle.IsOracleResponse](&lib_oracle.IsOracleResponse{}),
			"OracleClient":     gojs.GetClassConstructor[lib_oracle.OracleClient](&lib_oracle.OracleClient{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
