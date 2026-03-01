/**
 * Orchestrator: runs all 5 verification steps sequentially.
 *
 * Steps:
 * 1. Parse COSE_Sign1 (CBOR decode, syntactical validation)
 * 2. Verify certificate chain (root → intermediates → leaf)
 * 3. Verify COSE signature (ECDSA P-384/SHA-384)
 * 4. Compare PCR values
 * 5. Verify output hash
 *
 * Calls onStepUpdate callback per step for real-time UI updates.
 * On failure, remaining steps are marked as "skipped".
 */
import { parseCoseSign1 } from "./parse";
import { verifyCertificateChain } from "./cert-chain";
import { verifyCoseSignature } from "./signature";
import { comparePcrs } from "./pcr";
import { verifyOutputHash } from "./output";
import type {
  VerificationResult,
  VerificationOptions,
  VerificationStep,
  StepId,
  ParsedAttestation,
  CertChainInfo,
} from "./types";

const STEP_DEFINITIONS: { id: StepId; label: string }[] = [
  { id: "parse", label: "Parse Attestation Document" },
  { id: "cert-chain", label: "Verify Certificate Chain" },
  { id: "signature", label: "Verify COSE Signature" },
  { id: "pcr-match", label: "Compare PCR Values" },
  { id: "output-hash", label: "Verify Output Hash" },
];

function createInitialSteps(): VerificationStep[] {
  return STEP_DEFINITIONS.map((def) => ({
    id: def.id,
    label: def.label,
    status: "pending",
  }));
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export async function verifyAttestation(
  attestationDocBase64: string,
  options?: VerificationOptions
): Promise<VerificationResult> {
  const steps = createInitialSteps();
  const onUpdate = options?.onStepUpdate;
  let attestation: ParsedAttestation | null = null;
  let certChainInfo: CertChainInfo | null = null;

  const updateStep = (
    stepId: StepId,
    update: Partial<VerificationStep>
  ) => {
    const step = steps.find((s) => s.id === stepId);
    if (step) Object.assign(step, update);
    onUpdate?.(stepId, update);
  };

  const skipRemaining = (fromIndex: number) => {
    for (let i = fromIndex; i < steps.length; i++) {
      if (steps[i].status === "pending") {
        updateStep(steps[i].id, { status: "skipped" });
      }
    }
  };

  /**
   * Execute a single verification step with timing, error handling,
   * and step status updates.
   *
   * @returns The step's return value on success, or undefined on failure (early return from verifyAttestation).
   */
  async function runStep<T>(
    stepIndex: number,
    fn: () => T | Promise<T>,
    successMessage: (result: T) => string,
  ): Promise<{ ok: true; value: T } | { ok: false; result: VerificationResult }> {
    const stepId = STEP_DEFINITIONS[stepIndex].id;
    updateStep(stepId, { status: "running" });
    const t = performance.now();
    try {
      const value = await fn();
      const dur = Math.round(performance.now() - t);
      updateStep(stepId, {
        status: "passed",
        message: successMessage(value),
        durationMs: dur,
      });
      return { ok: true, value };
    } catch (e) {
      const dur = Math.round(performance.now() - t);
      const msg = errorMessage(e);
      updateStep(stepId, { status: "failed", message: msg, durationMs: dur });
      skipRemaining(stepIndex + 1);
      return { ok: false, result: buildResult("complete", false, steps, attestation, certChainInfo, msg) };
    }
  }

  try {
    // Step 1: Parse COSE_Sign1
    const parseResult = await runStep(
      0,
      () => parseCoseSign1(attestationDocBase64),
      (att) => `Module: ${att.moduleId}, ${Object.keys(att.pcrs).length} PCRs`,
    );
    if (!parseResult.ok) return parseResult.result;
    attestation = parseResult.value;

    // Step 2: Verify certificate chain
    const chainResult = await runStep(
      1,
      () => verifyCertificateChain(
        attestation!.certificate,
        attestation!.cabundle,
        { allowExpired: options?.allowExpired }
      ),
      (info) => `Chain depth: ${info.depth}, root: ${info.root.cn}`,
    );
    if (!chainResult.ok) return chainResult.result;
    certChainInfo = chainResult.value;

    // Step 3: Verify COSE signature
    const sigResult = await runStep(
      2,
      () => verifyCoseSignature(
        attestation!.rawProtected,
        attestation!.rawPayload,
        attestation!.rawSignature,
        attestation!.certificate
      ),
      () => "ECDSA P-384/SHA-384 signature valid",
    );
    if (!sigResult.ok) return sigResult.result;

    // Step 4: Compare PCR values
    const hasExpectedPcrs = !!(
      options?.expectedPcrs?.pcr0 ||
      options?.expectedPcrs?.pcr1 ||
      options?.expectedPcrs?.pcr2
    );
    const pcrResult = await runStep(
      3,
      () => comparePcrs(attestation!.pcrs, options?.expectedPcrs),
      () => hasExpectedPcrs
        ? "All expected PCR values match"
        : "No expected PCRs provided (skipped comparison)",
    );
    if (!pcrResult.ok) return pcrResult.result;

    // Step 5: Verify output hash
    const hasExpectedHash = !!options?.expectedOutputHash;
    const hashResult = await runStep(
      4,
      () => verifyOutputHash(attestation!.userData, options?.expectedOutputHash),
      () => hasExpectedHash
        ? "Output hash matches attestation"
        : "No expected output hash provided (skipped comparison)",
    );
    if (!hashResult.ok) return hashResult.result;

    // All steps passed
    return buildResult("complete", true, steps, attestation, certChainInfo);
  } catch (e) {
    return buildResult(
      "complete",
      false,
      steps,
      attestation,
      certChainInfo,
      errorMessage(e)
    );
  }
}

function buildResult(
  status: VerificationResult["status"],
  valid: boolean | null,
  steps: VerificationStep[],
  attestation: ParsedAttestation | null,
  certChainInfo: CertChainInfo | null,
  error?: string
): VerificationResult {
  return { status, valid, steps, attestation, certChainInfo, error };
}
