package rsync

import (
	lib_rsync "ManScan/pkg/js/libs/rsync"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/rsync")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"IsRsync": lib_rsync.IsRsync,

			// Var and consts

			// Objects / Classes
			"IsRsyncResponse":   gojs.GetClassConstructor[lib_rsync.IsRsyncResponse](&lib_rsync.IsRsyncResponse{}),
			"RsyncClient":       gojs.GetClassConstructor[lib_rsync.RsyncClient](&lib_rsync.RsyncClient{}),
			"RsyncListResponse": gojs.GetClassConstructor[lib_rsync.RsyncListResponse](&lib_rsync.RsyncListResponse{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
