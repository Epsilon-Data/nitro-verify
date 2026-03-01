/**
 * Step 5: Output hash verification.
 *
 * Verifies that the output_hash embedded in the attestation's user_data
 * matches the expected output hash. This proves the execution output
 * has not been tampered with after it was produced inside the enclave.
 */

/**
 * Verify the output hash from the attestation's user_data.
 *
 * @param userData - Parsed user_data from attestation
 * @param expectedOutputHash - Expected SHA-256 hash of the output
 * @returns true if hash matches or no expected hash provided
 * @throws Error if hashes don't match
 */
export function verifyOutputHash(
  userData: Record<string, unknown> | null,
  expectedOutputHash?: string | null
): boolean {
  if (!expectedOutputHash) return true;

  if (!userData) {
    throw new Error("No user_data in attestation to verify output hash");
  }

  const attestationHash = userData["output_hash"];
  if (!attestationHash || typeof attestationHash !== "string") {
    throw new Error("No output_hash found in attestation user_data");
  }

  if (attestationHash.toLowerCase() !== expectedOutputHash.toLowerCase()) {
    throw new Error(
      `Output hash mismatch: attestation has ${attestationHash}, expected ${expectedOutputHash}`
    );
  }

  return true;
}
