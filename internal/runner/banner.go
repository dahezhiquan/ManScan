// Package runner executes the enumeration process.
package runner

import (
	"fmt"

	"ManScan/pkg/catalog/config"

	"github.com/projectdiscovery/gologger"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	updateutils "github.com/projectdiscovery/utils/update"
)

var banner = fmt.Sprintf(`
 _____ ______   ________  ________   ________  ________  ________  ________      
|\   _ \  _   \|\   __  \|\   ___  \|\   ____\|\   ____\|\   __  \|\   ___  \    
\ \  \\\__\ \  \ \  \|\  \ \  \\ \  \ \  \___|\ \  \___|\ \  \|\  \ \  \\ \  \   
 \ \  \\|__| \  \ \   __  \ \  \\ \  \ \_____  \ \  \    \ \   __  \ \  \\ \  \  
  \ \  \    \ \  \ \  \ \  \ \  \\ \  \|____|\  \ \  \____\ \  \ \  \ \  \\ \  \ 
   \ \__\    \ \__\ \__\ \__\ \__\\ \__\____\_\  \ \_______\ \__\ \__\ \__\\ \__\
    \|__|     \|__|\|__|\|__|\|__| \|__|\_________\|_______|\|__|\|__|\|__| \|__|
                                       \|_________|                              
  %s
`, config.Version)

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tmanscan\n\n")
}

// NucleiToolUpdateCallback updates nuclei binary/tool to latest version
func NucleiToolUpdateCallback() {
	showBanner()
	updateutils.GetUpdateToolCallback(config.BinaryName, config.Version)()
}

// AuthWithPDCP is used to authenticate with PDCP
func AuthWithPDCP() {
	showBanner()
	pdcpauth.CheckNValidateCredentials(config.BinaryName)
}
