package smtp

import (
	lib_smtp "ManScan/pkg/js/libs/smtp"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/smtp")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewSMTPClient": lib_smtp.NewSMTPClient,

			// Var and consts

			// Objects / Classes
			"Client":       lib_smtp.NewSMTPClient,
			"SMTPMessage":  gojs.GetClassConstructor[lib_smtp.SMTPMessage](&lib_smtp.SMTPMessage{}),
			"SMTPResponse": gojs.GetClassConstructor[lib_smtp.SMTPResponse](&lib_smtp.SMTPResponse{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
