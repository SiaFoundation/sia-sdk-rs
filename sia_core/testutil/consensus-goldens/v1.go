package main

import (
	"encoding/hex"
	"fmt"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

func v1UnlockConditions() []struct {
	name string
	uc   types.UnlockConditions
} {
	entropy := make([]byte, 17)
	fill(entropy, 33)
	unknown := make([]byte, 45)
	fill(unknown, 44)
	return []struct {
		name string
		uc   types.UnlockConditions
	}{
		{"empty", types.UnlockConditions{PublicKeys: []types.UnlockKey{}}},
		{"standard", types.StandardUnlockConditions(publicKey(1))},
		{"timelocked", types.UnlockConditions{Timelock: 0x0102030405060708, PublicKeys: []types.UnlockKey{publicKey(2).UnlockKey()}, SignaturesRequired: 1}},
		{"multisig", types.UnlockConditions{Timelock: 123, PublicKeys: []types.UnlockKey{publicKey(3).UnlockKey(), publicKey(4).UnlockKey(), publicKey(5).UnlockKey()}, SignaturesRequired: 2}},
		{"entropy", types.UnlockConditions{PublicKeys: []types.UnlockKey{{Algorithm: types.SpecifierEntropy, Key: entropy}}, SignaturesRequired: 1}},
		{"unknown_algorithm", types.UnlockConditions{PublicKeys: []types.UnlockKey{{Algorithm: types.NewSpecifier("futurekey"), Key: unknown}}, SignaturesRequired: 1}},
		{"mixed_algorithms", types.UnlockConditions{Timelock: 789, PublicKeys: []types.UnlockKey{publicKey(6).UnlockKey(), {Algorithm: types.SpecifierEntropy, Key: entropy}, {Algorithm: types.NewSpecifier("futurekey"), Key: unknown}}, SignaturesRequired: 2}},
	}
}

func v1Transaction() types.Transaction {
	var txn types.Transaction
	for i := range 2 {
		seed := byte(10 + i*40)
		uc := types.UnlockConditions{Timelock: uint64(5 + i), PublicKeys: []types.UnlockKey{publicKey(seed).UnlockKey(), publicKey(seed + 1).UnlockKey()}, SignaturesRequired: 2}
		fc := types.FileContract{
			Filesize: uint64(12345 + i), FileMerkleRoot: hash256(seed + 2), WindowStart: uint64(1000 + i), WindowEnd: uint64(2000 + i),
			Payout:             types.NewCurrency(uint64(0x0102030405060708+i), uint64(0x1020304050607080+i)),
			ValidProofOutputs:  []types.SiacoinOutput{{Value: types.NewCurrency64(uint64(123 + i)), Address: address(seed + 3)}, {Value: types.NewCurrency64(uint64(456 + i)), Address: address(seed + 4)}},
			MissedProofOutputs: []types.SiacoinOutput{{Value: types.NewCurrency64(uint64(789 + i)), Address: address(seed + 5)}, {Value: types.NewCurrency64(uint64(987 + i)), Address: address(seed + 6)}},
			UnlockHash:         address(seed + 7), RevisionNumber: uint64(321 + i),
		}
		txn.SiacoinInputs = append(txn.SiacoinInputs, types.SiacoinInput{ParentID: types.SiacoinOutputID(hash256(seed + 8)), UnlockConditions: uc})
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{Value: types.NewCurrency(uint64(765+i), uint64(432+i)), Address: address(seed + 9)})
		txn.FileContracts = append(txn.FileContracts, fc)
		fc.Filesize += 111
		fc.RevisionNumber += 222
		txn.FileContractRevisions = append(txn.FileContractRevisions, types.FileContractRevision{ParentID: types.FileContractID(hash256(seed + 10)), UnlockConditions: uc, FileContract: fc})
		proof := types.StorageProof{ParentID: types.FileContractID(hash256(seed + 11)), Proof: []types.Hash256{hash256(seed + 12), hash256(seed + 13)}}
		fill(proof.Leaf[:], seed+14)
		txn.StorageProofs = append(txn.StorageProofs, proof)
		txn.SiafundInputs = append(txn.SiafundInputs, types.SiafundInput{ParentID: types.SiafundOutputID(hash256(seed + 15)), UnlockConditions: uc, ClaimAddress: address(seed + 16)})
		txn.SiafundOutputs = append(txn.SiafundOutputs, types.SiafundOutput{Value: uint64(256 + i), Address: address(seed + 17)})
		txn.MinerFees = append(txn.MinerFees, types.NewCurrency(uint64(254+i), uint64(i)))
		txn.ArbitraryData = append(txn.ArbitraryData, []byte{seed, 0, seed + 1, 255, seed + 2})
		sig := signature(seed + 18)
		txn.Signatures = append(txn.Signatures, types.TransactionSignature{ParentID: hash256(seed + 19), PublicKeyIndex: uint64(3 + i), Timelock: uint64(4 + i), CoveredFields: types.CoveredFields{WholeTransaction: true}, Signature: sig[:]})
	}
	return txn
}

func rawUnlockConditions(uc types.UnlockConditions) any {
	keys := make([]any, len(uc.PublicKeys))
	for i, key := range uc.PublicKeys {
		keys[i] = map[string]any{"algorithm": hex.EncodeToString(key.Algorithm[:]), "key": hex.EncodeToString(key.Key)}
	}
	return map[string]any{"timelock": uc.Timelock, "publicKeys": keys, "signaturesRequired": uc.SignaturesRequired}
}

func v1Vectors() any {
	var cases []any
	for _, test := range v1UnlockConditions() {
		cases = append(cases, map[string]any{"kind": "unlockConditions", "name": test.name, "object": rawUnlockConditions(test.uc), "binary": encode(test.uc), "address": test.uc.UnlockHash()})
	}
	var network consensus.Network
	network.HardforkASIC.Height = 10
	network.HardforkFoundation.Height = 20
	network.HardforkV2.AllowHeight = 30
	for _, test := range []struct {
		name string
		txn  types.Transaction
	}{{"empty", types.Transaction{}}, {"all_fields", v1Transaction()}} {
		txn := test.txn
		var siacoinIDs []types.SiacoinOutputID
		var siafundIDs []types.SiafundOutputID
		var contractIDs []types.FileContractID
		for i := range txn.SiacoinOutputs {
			siacoinIDs = append(siacoinIDs, txn.SiacoinOutputID(i))
		}
		for i := range txn.SiafundOutputs {
			siafundIDs = append(siafundIDs, txn.SiafundOutputID(i))
		}
		for i := range txn.FileContracts {
			contractIDs = append(contractIDs, txn.FileContractID(i))
		}
		type signatureVariant struct {
			name    string
			covered []uint64
			partial types.CoveredFields
		}
		var sigCases []any
		for _, height := range []uint64{0, 9, 10, 19, 20, 29, 30, 31} {
			cs := consensus.State{Network: &network, Index: types.ChainIndex{Height: height}}
			variants := []signatureVariant{{"none", []uint64{}, types.CoveredFields{}}}
			if test.name == "all_fields" {
				variants = append(variants,
					signatureVariant{"all_reversed", []uint64{1, 0}, types.CoveredFields{
						SiacoinInputs: []uint64{1, 0}, SiacoinOutputs: []uint64{1, 0}, FileContracts: []uint64{1, 0}, FileContractRevisions: []uint64{1, 0}, StorageProofs: []uint64{1, 0},
						SiafundInputs: []uint64{1, 0}, SiafundOutputs: []uint64{1, 0}, MinerFees: []uint64{1, 0}, ArbitraryData: []uint64{1, 0}, Signatures: []uint64{1, 0},
					}},
					signatureVariant{"selected", []uint64{1}, types.CoveredFields{SiacoinInputs: []uint64{1}, FileContractRevisions: []uint64{0}, SiafundOutputs: []uint64{1}, ArbitraryData: []uint64{0}, Signatures: []uint64{1}}},
				)
			}
			for _, variant := range variants {
				parentID := hash256(201)
				const keyIndex, timelock = 0x0102030405060708, 0x1020304050607080
				sigCases = append(sigCases, map[string]any{
					"name": fmt.Sprintf("height_%d_%s", height, variant.name), "height": height, "parentID": parentID, "publicKeyIndex": keyIndex, "timelock": timelock,
					"coveredSignatures": variant.covered, "wholeSigHash": cs.WholeSigHash(txn, parentID, keyIndex, timelock, variant.covered),
					"coveredFieldsBinary": encode(variant.partial), "partialSigHash": cs.PartialSigHash(txn, variant.partial),
				})
			}
		}
		cases = append(cases, map[string]any{
			"kind": "transaction", "name": test.name, "object": txn, "binary": encode(txn), "id": txn.ID(),
			"siacoinOutputIDs": siacoinIDs, "siafundOutputIDs": siafundIDs, "fileContractIDs": contractIDs, "signatures": sigCases,
		})
	}
	return cases
}
