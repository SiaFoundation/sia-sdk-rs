package main

import (
	"fmt"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

func v2Currency(seed byte) types.Currency {
	return types.NewCurrency(0xfedcba9876543210+uint64(seed), uint64(seed))
}

func v2Output(seed byte) types.SiacoinOutput {
	return types.SiacoinOutput{Value: v2Currency(seed), Address: address(seed + 1)}
}

func v2StateElement(seed byte) types.StateElement {
	return types.StateElement{
		LeafIndex:   0x1234567800000000 + uint64(seed),
		MerkleProof: []types.Hash256{hash256(seed), hash256(seed + 1)},
	}
}

func v2Contract(seed byte) types.V2FileContract {
	return types.V2FileContract{
		Capacity:       0x0102030405060708 + uint64(seed),
		Filesize:       0x1122334455667788 + uint64(seed),
		FileMerkleRoot: hash256(seed),
		ProofHeight:    700000 + uint64(seed), ExpirationHeight: 704320 + uint64(seed),
		RenterOutput: v2Output(seed + 1), HostOutput: v2Output(seed + 2),
		MissedHostValue: v2Currency(seed + 3), TotalCollateral: v2Currency(seed + 4),
		RenterPublicKey: publicKey(seed + 5), HostPublicKey: publicKey(seed + 6),
		RevisionNumber:  0x8877665544332211 + uint64(seed),
		RenterSignature: signature(seed + 7), HostSignature: signature(seed + 8),
	}
}

func v2ContractElement(seed byte) types.V2FileContractElement {
	return types.V2FileContractElement{
		StateElement: v2StateElement(seed), ID: types.FileContractID(hash256(seed + 1)),
		V2FileContract: v2Contract(seed + 2),
	}
}

func v2Renewal(seed byte) types.V2FileContractRenewal {
	return types.V2FileContractRenewal{
		FinalRenterOutput: v2Output(seed), FinalHostOutput: v2Output(seed + 1),
		RenterRollover: v2Currency(seed + 2), HostRollover: v2Currency(seed + 3),
		NewContract:     v2Contract(seed + 4),
		RenterSignature: signature(seed + 5), HostSignature: signature(seed + 6),
	}
}

func v2Attestation(seed byte) types.Attestation {
	return types.Attestation{
		PublicKey: publicKey(seed), Key: "HostAnnouncement", Value: []byte{seed, 0, seed + 1, 255},
		Signature: signature(seed + 2),
	}
}

func v2Transaction() types.V2Transaction {
	renewal := v2Renewal(60)
	proof := types.V2StorageProof{
		ProofIndex: types.ChainIndexElement{
			StateElement: v2StateElement(70), ID: types.BlockID(hash256(71)),
			ChainIndex: types.ChainIndex{Height: 654321, ID: types.BlockID(hash256(72))},
		},
		Proof: []types.Hash256{hash256(73), hash256(74)},
	}
	fill(proof.Leaf[:], 75)
	foundation := address(90)
	return types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent: types.SiacoinElement{
				StateElement: v2StateElement(1), ID: types.SiacoinOutputID(hash256(2)),
				SiacoinOutput: v2Output(3), MaturityHeight: 543210,
			},
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: types.PolicyPublicKey(publicKey(4)), Signatures: []types.Signature{signature(5)},
			},
		}},
		SiacoinOutputs: []types.SiacoinOutput{v2Output(6), v2Output(7)},
		SiafundInputs: []types.V2SiafundInput{{
			Parent: types.SiafundElement{
				StateElement: v2StateElement(10), ID: types.SiafundOutputID(hash256(11)),
				SiafundOutput: types.SiafundOutput{Value: 4321, Address: address(12)}, ClaimStart: v2Currency(13),
			},
			ClaimAddress: address(14),
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: types.PolicyHash(hash256(15)), Preimages: [][32]byte{[32]byte(hash256(16))},
			},
		}},
		SiafundOutputs:        []types.SiafundOutput{{Value: 1234, Address: address(17)}, {Value: 9876, Address: address(18)}},
		FileContracts:         []types.V2FileContract{v2Contract(20), v2Contract(21)},
		FileContractRevisions: []types.V2FileContractRevision{{Parent: v2ContractElement(30), Revision: v2Contract(40)}},
		FileContractResolutions: []types.V2FileContractResolution{
			{Parent: v2ContractElement(50), Resolution: &renewal},
			{Parent: v2ContractElement(51), Resolution: &proof},
			{Parent: v2ContractElement(52), Resolution: &types.V2FileContractExpiration{}},
		},
		Attestations:  []types.Attestation{v2Attestation(80), v2Attestation(81)},
		ArbitraryData: []byte{0, 7, 255, 128, 1}, NewFoundationAddress: &foundation, MinerFee: v2Currency(100),
	}
}

func v2TransactionVector(name string, txn types.V2Transaction) map[string]any {
	var cs consensus.State
	id := txn.ID()
	outputs := map[string][]string{"siacoin": {}, "siafund": {}, "file_contract": {}, "attestation": {}}
	for i := range txn.SiacoinOutputs {
		outputs["siacoin"] = append(outputs["siacoin"], txn.SiacoinOutputID(id, i).String())
	}
	for i := range txn.SiafundOutputs {
		outputs["siafund"] = append(outputs["siafund"], txn.SiafundOutputID(id, i).String())
	}
	for i := range txn.FileContracts {
		outputs["file_contract"] = append(outputs["file_contract"], txn.V2FileContractID(id, i).String())
	}
	for i := range txn.Attestations {
		outputs["attestation"] = append(outputs["attestation"], txn.AttestationID(id, i).String())
	}
	return map[string]any{
		"name": name, "kind": "transaction", "object": txn, "wire": encode(txn),
		"hashes":     map[string]string{"id": id.String(), "input_sig_hash": cs.InputSigHash(txn).String()},
		"output_ids": outputs,
	}
}

func v2Vectors() any {
	var cases []map[string]any
	addTransaction := func(name string, txn types.V2Transaction) {
		cases = append(cases, v2TransactionVector(name, txn))
	}
	all := v2Transaction()
	addTransaction("transaction/zero", types.V2Transaction{})
	addTransaction("transaction/siacoin_inputs", types.V2Transaction{SiacoinInputs: all.SiacoinInputs})
	addTransaction("transaction/siacoin_outputs", types.V2Transaction{SiacoinOutputs: all.SiacoinOutputs})
	addTransaction("transaction/siafund_inputs", types.V2Transaction{SiafundInputs: all.SiafundInputs})
	addTransaction("transaction/siafund_outputs", types.V2Transaction{SiafundOutputs: all.SiafundOutputs})
	addTransaction("transaction/contracts", types.V2Transaction{FileContracts: all.FileContracts})
	addTransaction("transaction/revisions", types.V2Transaction{FileContractRevisions: all.FileContractRevisions})
	for i, kind := range []string{"renewal", "storage_proof", "expiration"} {
		addTransaction("transaction/"+kind, types.V2Transaction{FileContractResolutions: all.FileContractResolutions[i : i+1]})
	}
	addTransaction("transaction/attestations", types.V2Transaction{Attestations: all.Attestations})
	addTransaction("transaction/arbitrary_data", types.V2Transaction{ArbitraryData: all.ArbitraryData})
	addTransaction("transaction/miner_fee", types.V2Transaction{MinerFee: all.MinerFee})
	for _, first := range []byte{0, 1, 2, 255} {
		a := address(90)
		a[0] = first
		addTransaction(fmt.Sprintf("transaction/foundation_%d", first), types.V2Transaction{NewFoundationAddress: &a})
	}
	addTransaction("transaction/combined", all)

	mutate := func(name string, f func(*types.V2Transaction)) {
		txn := v2Transaction()
		f(&txn)
		addTransaction("transaction/"+name, txn)
	}
	mutate("input_witnesses", func(txn *types.V2Transaction) {
		txn.SiacoinInputs[0].Parent.StateElement = v2StateElement(110)
		txn.SiacoinInputs[0].Parent.SiacoinOutput = v2Output(111)
		txn.SiacoinInputs[0].Parent.MaturityHeight++
		txn.SiacoinInputs[0].SatisfiedPolicy.Signatures[0] = signature(112)
		txn.SiafundInputs[0].Parent.StateElement = v2StateElement(113)
		txn.SiafundInputs[0].Parent.ClaimStart = v2Currency(114)
		txn.SiafundInputs[0].ClaimAddress = address(115)
		txn.SiafundInputs[0].SatisfiedPolicy.Preimages[0] = [32]byte(hash256(116))
	})
	mutate("parent_contract_witnesses", func(txn *types.V2Transaction) {
		txn.FileContractRevisions[0].Parent.StateElement = v2StateElement(117)
		txn.FileContractRevisions[0].Parent.V2FileContract = v2Contract(118)
		for i := range txn.FileContractResolutions {
			txn.FileContractResolutions[i].Parent.StateElement = v2StateElement(119 + byte(i))
			txn.FileContractResolutions[i].Parent.V2FileContract = v2Contract(122 + byte(i))
		}
	})
	mutate("contract_signatures", func(txn *types.V2Transaction) {
		for i := range txn.FileContracts {
			txn.FileContracts[i].RenterSignature = signature(125 + byte(i))
			txn.FileContracts[i].HostSignature = signature(127 + byte(i))
		}
		txn.FileContractRevisions[0].Revision.RenterSignature = signature(129)
		txn.FileContractRevisions[0].Revision.HostSignature = signature(130)
		renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
		renewal.NewContract.RenterSignature = signature(131)
		renewal.NewContract.HostSignature = signature(132)
		renewal.RenterSignature = signature(133)
		renewal.HostSignature = signature(134)
	})
	mutate("proof_index_merkle_proof", func(txn *types.V2Transaction) {
		sp := txn.FileContractResolutions[1].Resolution.(*types.V2StorageProof)
		sp.ProofIndex.StateElement.MerkleProof = []types.Hash256{hash256(135)}
	})
	mutate("proof_index_leaf_index", func(txn *types.V2Transaction) {
		txn.FileContractResolutions[1].Resolution.(*types.V2StorageProof).ProofIndex.StateElement.LeafIndex++
	})
	mutate("proof_leaf", func(txn *types.V2Transaction) {
		txn.FileContractResolutions[1].Resolution.(*types.V2StorageProof).Leaf[0] ^= 1
	})
	mutate("proof_hashes", func(txn *types.V2Transaction) {
		txn.FileContractResolutions[1].Resolution.(*types.V2StorageProof).Proof[0] = hash256(136)
	})
	mutate("attestation_signature", func(txn *types.V2Transaction) {
		txn.Attestations[0].Signature = signature(137)
	})
	mutate("input_parent_id", func(txn *types.V2Transaction) {
		txn.SiacoinInputs[0].Parent.ID = types.SiacoinOutputID(hash256(138))
	})
	mutate("outputs_reordered", func(txn *types.V2Transaction) {
		txn.SiacoinOutputs[0], txn.SiacoinOutputs[1] = txn.SiacoinOutputs[1], txn.SiacoinOutputs[0]
	})

	var cs consensus.State
	addContract := func(name string, fc types.V2FileContract) {
		cases = append(cases, map[string]any{
			"name": "contract/" + name, "kind": "file_contract", "object": fc, "wire": encode(fc),
			"hashes": map[string]string{"signature_hash": cs.ContractSigHash(fc).String()},
			"tax":    cs.V2FileContractTax(fc).ExactString(),
		})
	}
	addContract("zero", types.V2FileContract{})
	fc := v2Contract(20)
	addContract("nonzero", fc)
	fc.RenterSignature, fc.HostSignature = signature(140), signature(141)
	addContract("signatures", fc)
	fc.RevisionNumber++
	addContract("revision", fc)
	for _, value := range []uint64{24, 25, 249999, 250001} {
		addContract(fmt.Sprintf("tax_%d", value), types.V2FileContract{RenterOutput: types.SiacoinOutput{Value: types.NewCurrency64(value)}})
	}
	addRenewal := func(name string, ren types.V2FileContractRenewal) {
		cases = append(cases, map[string]any{
			"name": "renewal/" + name, "kind": "renewal", "object": ren, "wire": encode(ren),
			"hashes": map[string]string{"signature_hash": cs.RenewalSigHash(ren).String()},
		})
	}
	addRenewal("zero", types.V2FileContractRenewal{})
	renewal := v2Renewal(60)
	addRenewal("nonzero", renewal)
	renewal.RenterSignature, renewal.HostSignature = signature(142), signature(143)
	renewal.NewContract.RenterSignature, renewal.NewContract.HostSignature = signature(144), signature(145)
	addRenewal("signatures", renewal)
	renewal.FinalRenterOutput.Value = renewal.FinalRenterOutput.Value.Add(types.NewCurrency64(1))
	addRenewal("final_renter_output", renewal)
	renewal = v2Renewal(60)
	renewal.FinalHostOutput.Address = address(146)
	addRenewal("final_host_output", renewal)
	renewal = v2Renewal(60)
	renewal.RenterRollover = renewal.RenterRollover.Add(types.NewCurrency64(1))
	addRenewal("renter_rollover", renewal)
	renewal = v2Renewal(60)
	renewal.HostRollover = renewal.HostRollover.Add(types.NewCurrency64(1))
	addRenewal("host_rollover", renewal)
	renewal = v2Renewal(60)
	renewal.NewContract.Filesize++
	addRenewal("new_contract", renewal)
	addAttestation := func(name string, a types.Attestation) {
		cases = append(cases, map[string]any{
			"name": "attestation/" + name, "kind": "attestation", "object": a, "wire": encode(a),
			"hashes": map[string]string{"signature_hash": cs.AttestationSigHash(a).String()},
		})
	}
	addAttestation("zero", types.Attestation{Value: []byte{}})
	a := v2Attestation(80)
	addAttestation("nonzero", a)
	a.Signature = signature(147)
	addAttestation("signature", a)
	a.Key += "Changed"
	addAttestation("key", a)
	a = v2Attestation(80)
	a.Value = []byte{0, 1, 2}
	addAttestation("value", a)
	a = v2Attestation(80)
	a.PublicKey = publicKey(148)
	addAttestation("public_key", a)
	return cases
}
