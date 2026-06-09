package krbforge

import (
	lib_krbforge "ManScan/pkg/js/libs/krbforge"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/krbforge")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"CreateGoldenTicket": lib_krbforge.CreateGoldenTicket,
			"CreateSilverTicket": lib_krbforge.CreateSilverTicket,

			// Var and consts

			// Objects / Classes
			"Ticket":        gojs.GetClassConstructor[lib_krbforge.Ticket](&lib_krbforge.Ticket{}),
			"TicketRequest": gojs.GetClassConstructor[lib_krbforge.TicketRequest](&lib_krbforge.TicketRequest{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
