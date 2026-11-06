package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"

	rhp "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
)

func rhpRequest(id types.Specifier, request rhp.Object) string {
	var buf bytes.Buffer
	if err := rhp.WriteRequest(&buf, id, request); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf.Bytes())
}

func rhpResponse(response rhp.Object) string {
	var buf bytes.Buffer
	if err := rhp.WriteResponse(&buf, response); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf.Bytes())
}

func rhp4Vectors() any {
	var cases []any
	for _, seed := range []byte{17, 139} {
		prices := rhp.HostPrices{
			ContractPrice: types.NewCurrency(101, 1), Collateral: types.NewCurrency(102, 2),
			StoragePrice: types.NewCurrency(103, 3), IngressPrice: types.NewCurrency(104, 4),
			EgressPrice: types.NewCurrency(105, 5), FreeSectorPrice: types.NewCurrency(106, 6),
			TipHeight: 0x123456789, ValidUntil: time.Unix(1700000000+int64(seed), 0).UTC(),
			Signature: signature(seed),
		}
		token := rhp.AccountToken{
			HostKey: publicKey(seed + 1), Account: rhp.Account(publicKey(seed + 2)),
			ValidUntil: time.Unix(1800000000+int64(seed), 0).UTC(), Signature: signature(seed + 3),
		}
		add := func(kind string, value any, expected map[string]any) {
			c := map[string]any{"name": fmt.Sprintf("%s_%d", kind, seed), "kind": kind, "value": value}
			for k, v := range expected {
				c[k] = v
			}
			cases = append(cases, c)
		}
		add("host_prices", prices, map[string]any{"hash": prices.SigHash(), "encoding": encode(prices)})
		add("account_token", token, map[string]any{"hash": token.SigHash()})

		basis := types.ChainIndex{Height: 0x23456789a, ID: types.BlockID(hash256(seed + 4))}
		inputs := []types.SiacoinElement{{
			StateElement:   types.StateElement{LeafIndex: 31, MerkleProof: []types.Hash256{hash256(seed + 5), hash256(seed + 6)}},
			ID:             types.SiacoinOutputID(hash256(seed + 7)),
			SiacoinOutput:  types.SiacoinOutput{Value: types.NewCurrency(107, 7), Address: address(seed + 8)},
			MaturityHeight: 101,
		}}
		parents := []types.V2Transaction{{SiacoinOutputs: []types.SiacoinOutput{{Value: types.NewCurrency(108, 8), Address: address(seed + 9)}}, MinerFee: types.NewCurrency(109, 9)}}
		contractID := types.FileContractID(hash256(seed + 10))
		challengeSignature := signature(seed + 11)
		revision := uint64(0x3456789ab)
		free := rhp.RPCFreeSectorsRequest{Prices: prices, ContractID: contractID, Indices: []uint64{1, 29, 257}, ChallengeSignature: challengeSignature}
		add("free_sectors", free, map[string]any{"hash": free.ChallengeSigHash(revision), "revisionNumber": revision, "wire": rhpRequest(rhp.RPCFreeSectorsID, &free)})
		appendReq := rhp.RPCAppendSectorsRequest{Prices: prices, Sectors: []types.Hash256{hash256(seed + 12), hash256(seed + 13)}, ContractID: contractID, ChallengeSignature: challengeSignature}
		add("append_sectors", appendReq, map[string]any{"hash": appendReq.ChallengeSigHash(revision), "revisionNumber": revision, "wire": rhpRequest(rhp.RPCAppendSectorsID, &appendReq)})
		renew := rhp.RPCRenewContractRequest{
			Prices: prices, Renewal: rhp.RPCRenewContractParams{ContractID: contractID, Allowance: types.NewCurrency(110, 10), Collateral: types.NewCurrency(111, 11), ProofHeight: 0x456789abc},
			MinerFee: types.NewCurrency(112, 12), Basis: basis, RenterInputs: inputs, RenterParents: parents, ChallengeSignature: challengeSignature,
		}
		add("renew_contract", renew, map[string]any{"hash": renew.ChallengeSigHash(revision), "revisionNumber": revision, "wire": rhpRequest(rhp.RPCRenewContractID, &renew)})
		refresh := rhp.RPCRefreshContractRequest{
			Prices: prices, Refresh: rhp.RPCRefreshContractParams{ContractID: contractID, Allowance: types.NewCurrency(113, 13), Collateral: types.NewCurrency(114, 14)},
			MinerFee: types.NewCurrency(115, 15), Basis: basis, RenterInputs: inputs, RenterParents: parents, ChallengeSignature: challengeSignature,
		}
		add("refresh_contract", refresh, map[string]any{"hash": refresh.ChallengeSigHash(revision), "revisionNumber": revision, "wire": rhpRequest(rhp.RPCRefreshContractID, &refresh)})
		replenish := rhp.RPCReplenishAccountsRequest{Accounts: []rhp.Account{rhp.Account(publicKey(seed + 14)), rhp.Account(publicKey(seed + 15))}, Target: types.NewCurrency(116, 16), ContractID: contractID, ChallengeSignature: challengeSignature}
		add("replenish_accounts", replenish, map[string]any{"hash": replenish.ChallengeSigHash(revision), "revisionNumber": revision, "wire": rhpRequest(rhp.RPCReplenishAccountsID, &replenish)})

		form := rhp.RPCFormContractRequest{
			Prices: prices, Contract: rhp.RPCFormContractParams{RenterPublicKey: publicKey(seed + 16), RenterAddress: address(seed + 17), Allowance: types.NewCurrency(117, 17), Collateral: types.NewCurrency(118, 18), ProofHeight: 0x56789abcd},
			MinerFee: types.NewCurrency(119, 19), Basis: basis, RenterInputs: inputs, RenterParents: parents,
		}
		add("form_contract", form, map[string]any{"wire": rhpRequest(rhp.RPCFormContractID, &form)})
		formSigs := rhp.RPCFormContractSecondResponse{
			RenterContractSignature: signature(seed + 18),
			RenterSatisfiedPolicies: []types.SatisfiedPolicy{{Policy: types.PolicyPublicKey(publicKey(seed + 19)), Signatures: []types.Signature{signature(seed + 20)}}},
		}
		add("form_contract_signatures", formSigs, map[string]any{"wire": rhpResponse(&formSigs)})
		read := rhp.RPCReadSectorRequest{Prices: prices, Token: token, Root: hash256(seed + 21), Offset: 128, Length: 192}
		add("read_sector", read, map[string]any{"wire": rhpRequest(rhp.RPCReadSectorID, &read)})
		write := rhp.RPCWriteSectorRequest{Prices: prices, Token: token, DataLength: 256}
		add("write_sector", write, map[string]any{"wire": rhpRequest(rhp.RPCWriteSectorID, &write)})
	}
	return cases
}
