package main

import "go.sia.tech/coreutils/chain"

func networkVectors() any {
	mainnet, _ := chain.Mainnet()
	zen, _ := chain.TestnetZen()
	mainnet.HardforkOak.GenesisTimestamp = mainnet.HardforkOak.GenesisTimestamp.UTC()
	zen.HardforkOak.GenesisTimestamp = zen.HardforkOak.GenesisTimestamp.UTC()
	return []any{mainnet, zen}
}
