package main

import (
	"fmt"

	"go.sia.tech/core/types"
)

func idVectors() any {
	var cases []map[string]any
	for _, seed := range []byte{0, 1, 255} {
		bid := types.BlockID(hash256(seed))
		sfid := types.SiafundOutputID(hash256(seed))
		fcid := types.FileContractID(hash256(seed))
		for _, index := range []uint64{0, 1, 0x0123456789abcdef, ^uint64(0)} {
			cases = append(cases, map[string]any{
				"name": fmt.Sprintf("block_%d_%d", seed, index), "kind": "block",
				"id": bid, "index": index,
				"minerOutputID": bid.MinerOutputID(int(index)), "foundationOutputID": bid.FoundationOutputID(),
			}, map[string]any{
				"name": fmt.Sprintf("contract_%d_%d", seed, index), "kind": "contract",
				"id": fcid, "index": index,
				"validOutputID": fcid.ValidOutputID(int(index)), "missedOutputID": fcid.MissedOutputID(int(index)),
				"renterOutputID": fcid.V2RenterOutputID(), "hostOutputID": fcid.V2HostOutputID(), "renewalID": fcid.V2RenewalID(),
			})
		}
		cases = append(cases, map[string]any{
			"name": fmt.Sprintf("siafund_%d", seed), "kind": "siafund", "id": sfid,
			"claimOutputID": sfid.ClaimOutputID(), "v2ClaimOutputID": sfid.V2ClaimOutputID(),
		})
	}
	for _, txn := range []types.V2Transaction{
		{},
		{
			SiacoinOutputs: []types.SiacoinOutput{{Value: types.NewCurrency(123, 456), Address: address(1)}},
			SiafundOutputs: []types.SiafundOutput{{Value: 789, Address: address(2)}},
			ArbitraryData:  []byte{0, 1, 255}, MinerFee: types.NewCurrency(987, 654),
		},
	} {
		txid := txn.ID()
		for _, index := range []uint64{0, 1, 0x0123456789abcdef, ^uint64(0)} {
			cases = append(cases, map[string]any{
				"name": fmt.Sprintf("transaction_%s_%d", txid, index), "kind": "transaction",
				"binary": encode(txn), "id": txid, "index": index,
				"siacoinOutputID": txn.SiacoinOutputID(txid, int(index)),
				"siafundOutputID": txn.SiafundOutputID(txid, int(index)),
				"fileContractID":  txn.V2FileContractID(txid, int(index)),
				"attestationID":   txn.AttestationID(txid, int(index)),
			})
		}
	}
	return cases
}
