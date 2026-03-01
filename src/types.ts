export type StepId = "parse" | "cert-chain" | "signature" | "pcr-match" | "output-hash";
export type StepStatus = "pending" | "running" | "passed" | "failed" | "skipped";

export interface VerificationStep {
  id: StepId;
  label: string;
  status: StepStatus;
  message?: string;
  durationMs?: number;
}

export interface ParsedAttestation {
  moduleId: string;
  timestamp: number;
  digest: string;
  pcrs: Record<number, string>;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
  userData: Record<string, unknown> | null;
  nonce: Uint8Array | null;
  publicKey: Uint8Array | null;
  rawProtected: Uint8Array;
  rawPayload: Uint8Array;
  rawSignature: Uint8Array;
}

export interface CertChainInfo {
  depth: number;
  root: { cn: string; fingerprint: string };
  intermediateCount: number;
  endEntity: { cn: string; validFrom: string; validTo: string };
}

export interface VerificationResult {
  status: "idle" | "running" | "complete";
  valid: boolean | null;
  steps: VerificationStep[];
  attestation: ParsedAttestation | null;
  certChainInfo: CertChainInfo | null;
  error?: string;
}

export interface VerificationOptions {
  expectedPcrs?: { pcr0?: string; pcr1?: string; pcr2?: string } | null;
  expectedOutputHash?: string | null;
  /** Skip certificate date validation (for verifying historical attestations with expired short-lived certs). */
  allowExpired?: boolean;
  onStepUpdate?: (stepId: StepId, update: Partial<VerificationStep>) => void;
}
