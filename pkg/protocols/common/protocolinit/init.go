package protocolinit

import (
	"ManScan/pkg/js/compiler"
	"ManScan/pkg/protocols/common/protocolstate"
	"ManScan/pkg/protocols/dns/dnsclientpool"
	"ManScan/pkg/protocols/http/signerpool"
	"ManScan/pkg/protocols/network/networkclientpool"
	"ManScan/pkg/protocols/whois/rdapclientpool"
	"ManScan/pkg/types"
	_ "github.com/projectdiscovery/utils/global"
)

// Init initializes the client pools for the protocols
func Init(options *types.Options) error {
	if err := protocolstate.Init(options); err != nil {
		return err
	}
	if err := dnsclientpool.Init(options); err != nil {
		return err
	}
	if err := signerpool.Init(options); err != nil {
		return err
	}
	if err := networkclientpool.Init(options); err != nil {
		return err
	}
	if err := rdapclientpool.Init(options); err != nil {
		return err
	}
	if err := compiler.Init(options); err != nil {
		return err
	}
	return nil
}

func Close(executionId string) {
	protocolstate.Close(executionId)
}
