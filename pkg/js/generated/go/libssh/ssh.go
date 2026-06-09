package ssh

import (
	lib_ssh "ManScan/pkg/js/libs/ssh"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/ssh")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Objects / Classes
			"SSHClient": gojs.GetClassConstructor[lib_ssh.SSHClient](&lib_ssh.SSHClient{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
