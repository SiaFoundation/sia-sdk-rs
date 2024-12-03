import { Seed, UnlockConditions } from "sia_js";

function generateWallet() {
  const generateStart = performance.now();
  const s = Seed.generate(),
    address = new UnlockConditions({
      timelock: 0n,
      publicKeys: [s.privateKey(0).publicKey()],
      signaturesRequired: 1n,
    }).address();
  const perf = performance.now() - generateStart;
  document.getElementById("seed").innerText = s.toString();
  document.getElementById("address").innerText = address;
  document.getElementById("execution-speed").innerText =
    `Generated in ${perf}ms`;
}

generateWallet();

document.getElementById("wallet-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  try {
    generateWallet();
  } catch (ex) {
    console.error(ex);
  }
});
