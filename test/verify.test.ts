/**
 * Test script for @epsilon-data/nitro-verify
 *
 * Uses a real AWS Nitro Enclave attestation document from production (JOB-MLAM9VY0).
 * Certificates are fresh (Feb 6 2026), so full verification should pass.
 */
import { verifyAttestation } from "../src/index";
import { parseCoseSign1 } from "../src/parse";

// Real attestation document from epsilon production — JOB-MLAM9VY0 (Feb 6 2026)
const REAL_ATTESTATION_BASE64 = `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`;

// Expected PCR values from nitro-cli describe-enclaves (running enclave)
const EXPECTED_PCRS = {
  pcr0: "6165855369654a587bdad59fa532f430d7defa38ecf57eeac6d29c7e87a32b621891862d04fb64423f6bb1e1626fc026",
  pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
  pcr2: "a50f214952d1cc168b04da54db1b163a86e5ffefec223b7b640df88b665c3db745e9a6865a7db265374239fd264a5522",
};

// Expected output hash from user_data
const EXPECTED_OUTPUT_HASH = "890da9e8ca507c2fbbb4fbc50b882358d96b8efc3ef23bb8c05eca965513c775";

async function testParsing() {
  console.log("=== Test 1: COSE_Sign1 Parsing ===");
  try {
    const att = parseCoseSign1(REAL_ATTESTATION_BASE64);
    console.log("  moduleId:", att.moduleId);
    console.log("  digest:", att.digest);
    console.log("  timestamp:", att.timestamp, "->", new Date(att.timestamp).toISOString());
    console.log("  PCR count:", Object.keys(att.pcrs).length);
    console.log("  PCR0:", att.pcrs[0]);
    console.log("  PCR1:", att.pcrs[1]);
    console.log("  PCR2:", att.pcrs[2]);
    console.log("  certificate length:", att.certificate.length, "bytes");
    console.log("  cabundle length:", att.cabundle.length, "certs");
    console.log("  userData:", att.userData ? JSON.stringify(att.userData).substring(0, 120) + "..." : null);
    console.log("  nonce:", att.nonce ? `${att.nonce.length} bytes` : null);
    console.log("  signature length:", att.rawSignature.length, "bytes");
    console.log("  PASSED: Parsing succeeded\n");
    return att;
  } catch (e) {
    console.error("  FAILED:", e);
    return null;
  }
}

async function testFullVerification() {
  console.log("=== Test 2: Full Verification ===");
  const result = await verifyAttestation(REAL_ATTESTATION_BASE64, {
    expectedPcrs: EXPECTED_PCRS,
    expectedOutputHash: EXPECTED_OUTPUT_HASH,
    onStepUpdate: (stepId, update) => {
      if (update.status) {
        const icon = update.status === "passed" ? "\u2705" : update.status === "failed" ? "\u274C" : "\u23F3";
        console.log(`  ${icon} ${stepId}: ${update.status}${update.message ? " — " + update.message : ""}${update.durationMs !== undefined ? ` (${update.durationMs}ms)` : ""}`);
      }
    },
  });

  console.log("\n  Overall valid:", result.valid);
  console.log("  Status:", result.status);
  if (result.error) console.log("  Error:", result.error);
  if (result.certChainInfo) {
    console.log("  Cert chain depth:", result.certChainInfo.depth);
    console.log("  Root CN:", result.certChainInfo.root.cn);
    console.log("  Root fingerprint:", result.certChainInfo.root.fingerprint);
    console.log("  End entity:", result.certChainInfo.endEntity.cn);
    console.log("  Valid from:", result.certChainInfo.endEntity.validFrom);
    console.log("  Valid to:", result.certChainInfo.endEntity.validTo);
  }
  console.log();
  return result;
}

async function testVerificationWithoutPcrs() {
  console.log("=== Test 3: Verification Without Expected PCRs (skip PCR check) ===");
  const result = await verifyAttestation(REAL_ATTESTATION_BASE64, {
    onStepUpdate: (stepId, update) => {
      if (update.status) {
        const icon = update.status === "passed" ? "\u2705" : update.status === "failed" ? "\u274C" : update.status === "skipped" ? "\u23ED\uFE0F" : "\u23F3";
        console.log(`  ${icon} ${stepId}: ${update.status}${update.message ? " — " + update.message : ""}`);
      }
    },
  });

  console.log("\n  Overall valid:", result.valid);
  console.log();
  return result;
}

async function testVerificationWithWrongPcr() {
  console.log("=== Test 4: Verification With Wrong PCR (should fail) ===");
  const result = await verifyAttestation(REAL_ATTESTATION_BASE64, {
    expectedPcrs: {
      pcr0: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    },
    onStepUpdate: (stepId, update) => {
      if (update.status) {
        const icon = update.status === "passed" ? "\u2705" : update.status === "failed" ? "\u274C" : update.status === "skipped" ? "\u23ED\uFE0F" : "\u23F3";
        console.log(`  ${icon} ${stepId}: ${update.status}${update.message ? " — " + update.message : ""}`);
      }
    },
  });

  console.log("\n  Overall valid:", result.valid, "(expected: false)");
  console.log();
  return result;
}

async function main() {
  console.log("@epsilon-data/nitro-verify — Test Suite\n");

  await testParsing();
  const fullResult = await testFullVerification();
  await testVerificationWithoutPcrs();
  await testVerificationWithWrongPcr();

  // Summary
  console.log("=== Summary ===");
  console.log("  Full verification:", fullResult.valid ? "ALL PASSED" : "FAILED");
  console.log("=== Done ===");
}

main().catch(console.error);
