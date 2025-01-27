import { Seed, UnlockConditions } from "sia_js";

try {
  const s = Seed.generate(),
    sk = s.privateKey(0),
    address = new UnlockConditions({
      timelock: 0n,
      publicKeys: [sk.publicKey()],
      signaturesRequired: 1n,
    }).address();

  console.log(`Seed: ${s.toString()}`);
  console.log(`Address: ${address}`);
} catch (e) {
  console.error(e);
}

try {
  const txn = new Transaction();

  txn.siacoin_outputs.push({
    value: 100n,
    address:
      "8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0",
  });
  console.log(txn);
  console.log(txn.id());
} catch (ex) {
  console.error(ex);
}
