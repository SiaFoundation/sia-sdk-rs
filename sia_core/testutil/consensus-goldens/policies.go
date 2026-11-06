package main

import (
	"time"

	"go.sia.tech/core/types"
)

func policyVectors() any {
	pk := types.PolicyPublicKey(publicKey(17))
	hash := types.PolicyHash(hash256(31))
	opaque := types.PolicyOpaque(pk)
	nested := types.PolicyThreshold(2, []types.SpendPolicy{
		types.PolicyAbove(789),
		types.PolicyThreshold(1, []types.SpendPolicy{pk, hash, types.PolicyAfter(time.Unix(1700000001, 0))}),
		opaque,
	})
	tests := []struct {
		name string
		p    types.SpendPolicy
	}{
		{"above_zero", types.PolicyAbove(0)},
		{"above_nonzero", types.PolicyAbove(0x0102030405060708)},
		{"after_epoch", types.PolicyAfter(time.Unix(0, 0))},
		{"after_nonzero", types.PolicyAfter(time.Unix(1700000001, 0))},
		{"after_before_epoch", types.PolicyAfter(time.Unix(-1, 0))},
		{"public_key", pk},
		{"hash", hash},
		{"anyone_can_spend", types.AnyoneCanSpend()},
		{"threshold", types.PolicyThreshold(1, []types.SpendPolicy{pk, hash})},
		{"threshold_partial_opaque", types.PolicyThreshold(1, []types.SpendPolicy{opaque, hash})},
		{"threshold_all_opaque", types.PolicyThreshold(1, []types.SpendPolicy{opaque, types.PolicyOpaque(hash)})},
		{"nested_threshold", nested},
		{"nested_threshold_opaque", types.PolicyThreshold(2, []types.SpendPolicy{types.PolicyOpaque(types.PolicyAbove(789)), types.PolicyOpaque(types.PolicyThreshold(1, []types.SpendPolicy{pk, hash, types.PolicyAfter(time.Unix(1700000001, 0))})), opaque})},
		{"opaque", opaque},
		{"opaque_zero", types.SpendPolicy{Type: types.PolicyTypeOpaque(types.Address{})}},
	}
	for _, test := range v1UnlockConditions() {
		tests = append(tests, struct {
			name string
			p    types.SpendPolicy
		}{"unlock_conditions_" + test.name, types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(test.uc)}})
	}
	var cases []any
	for _, test := range tests {
		cases = append(cases, map[string]any{"kind": "policy", "name": test.name, "object": test.p, "binary": encode(test.p), "address": test.p.Address()})
	}
	for _, test := range []struct {
		name string
		sp   types.SatisfiedPolicy
	}{
		{"empty_satisfaction", types.SatisfiedPolicy{Policy: types.AnyoneCanSpend()}},
		{"signature", types.SatisfiedPolicy{Policy: pk, Signatures: []types.Signature{signature(61)}}},
		{"preimage", types.SatisfiedPolicy{Policy: hash, Preimages: [][32]byte{hash256(111)}}},
		{"signature_and_preimages", types.SatisfiedPolicy{Policy: nested, Signatures: []types.Signature{signature(71), signature(81)}, Preimages: [][32]byte{hash256(91), hash256(101)}}},
	} {
		cases = append(cases, map[string]any{"kind": "satisfied", "name": test.name, "object": test.sp, "binary": encode(test.sp), "policyAddress": test.sp.Policy.Address()})
	}
	return cases
}
