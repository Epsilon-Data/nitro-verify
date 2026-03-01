/**
 * Step 4: PCR (Platform Configuration Register) comparison.
 *
 * PCRs are hardware-measured hashes that identify the exact code
 * running in the enclave:
 * - PCR0: Hash of the Enclave Image File (EIF)
 * - PCR1: Hash of the Linux kernel and boot ramdisk
 * - PCR2: Hash of the application
 *
 * Comparison is case-insensitive hex string matching.
 */

/**
 * Compare attestation PCR values against expected values.
 *
 * @param attestationPcrs - PCR map from parsed attestation (index → hex)
 * @param expectedPcrs - Expected PCR values to verify against
 * @returns true if all provided expected PCRs match
 * @throws Error with details of mismatched PCRs
 */
export function comparePcrs(
  attestationPcrs: Record<number, string>,
  expectedPcrs?: { pcr0?: string; pcr1?: string; pcr2?: string } | null
): boolean {
  if (!expectedPcrs) return true;

  const errors: string[] = [];
  const checks: [number, string | undefined][] = [
    [0, expectedPcrs.pcr0],
    [1, expectedPcrs.pcr1],
    [2, expectedPcrs.pcr2],
  ];

  for (const [idx, expected] of checks) {
    if (!expected) continue;
    const actual = attestationPcrs[idx];
    if (!actual) {
      errors.push(`PCR${idx} missing from attestation`);
    } else if (actual.toLowerCase() !== expected.toLowerCase()) {
      errors.push(
        `PCR${idx} mismatch: got ${actual}, expected ${expected}`
      );
    }
  }

  if (errors.length > 0) {
    throw new Error(errors.join("; "));
  }

  return true;
}
