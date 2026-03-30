# @epsilon-data/nitro-verify

Cryptographic verification of AWS Nitro Enclave attestation documents — works in browsers (WebCrypto) and Node.js.

## What It Does

When code runs inside an AWS Nitro Enclave, the hardware generates a signed **attestation document** proving:

- The code ran on genuine AWS Nitro hardware (certificate chain to AWS root)
- The exact binary that ran (PCR values — hashes of the enclave image)
- The execution output hash (embedded in `user_data`, tamper-proof)

This library parses and cryptographically verifies those attestation documents.

## Install

```bash
npm install @epsilon-data/nitro-verify
```

## Usage

### Browser / Node.js Library

```typescript
import { verifyAttestation } from "@epsilon-data/nitro-verify";

const result = await verifyAttestation(attestationBase64, {
  // Optional: compare PCR values against expected
  expectedPcrs: {
    pcr0: "6165855369654a587bdad59fa532f430...",
    pcr1: "4b4d5b3661b3efc12920900c80e126e4...",
    pcr2: "a50f214952d1cc168b04da54db1b163a...",
  },
  // Optional: verify output hash
  expectedOutputHash: "890da9e8ca507c2fbbb4fbc50b882358...",
  // Optional: skip cert date validation for historical attestations
  allowExpired: true,
  // Optional: real-time step updates (for UI progress)
  onStepUpdate: (stepId, update) => {
    console.log(`${stepId}: ${update.status}`);
  },
});

console.log(result.valid); // true | false
console.log(result.steps); // detailed per-step results
console.log(result.attestation); // parsed attestation fields
console.log(result.certChainInfo); // certificate chain metadata
```

### CLI

```bash
# Verify from file
nitro-verify attestation.b64

# Verify with expected PCR values
nitro-verify attestation.b64 \
  --pcr0 6165855369654a587bdad59fa532f430d7defa38ecf57eeac6d29c7e87a32b621891862d04fb64423f6bb1e1626fc026

# Verify from stdin
cat attestation.b64 | nitro-verify --stdin

# Verify historical attestation (expired certs)
nitro-verify attestation.b64 --allow-expired

# Parse only (no crypto verification)
nitro-verify --parse attestation.b64

# JSON output
nitro-verify attestation.b64 --json
```

## Verification Steps

1. **Parse** — Decode the CBOR/COSE_Sign1 attestation document, validate structure per AWS spec
2. **Certificate Chain** — Verify chain from AWS Nitro root certificate to enclave leaf certificate
3. **Signature** — Verify the ES384 (ECDSA P-384/SHA-384) COSE_Sign1 signature
4. **PCR Match** — Compare PCR0/1/2 against expected values (if provided)
5. **Output Hash** — Verify SHA-256 of execution output matches attested `user_data` hash (if provided)

## API

### `verifyAttestation(attestationDocBase64, options?)`

Returns `Promise<VerificationResult>`.

#### Options

| Option | Type | Description |
|--------|------|-------------|
| `expectedPcrs` | `{ pcr0?, pcr1?, pcr2? }` | Expected PCR values to verify against |
| `expectedOutputHash` | `string` | Expected SHA-256 hash of execution output |
| `allowExpired` | `boolean` | Skip certificate date validation |
| `onStepUpdate` | `(stepId, update) => void` | Callback for real-time step progress |

#### Result

```typescript
interface VerificationResult {
  status: "idle" | "running" | "complete";
  valid: boolean | null;
  steps: VerificationStep[];
  attestation: ParsedAttestation | null;
  certChainInfo: CertChainInfo | null;
  error?: string;
}
```

### Full Type Reference

```typescript
// Verification step identifiers
type StepId = "parse" | "cert-chain" | "signature" | "pcr-match" | "output-hash";
type StepStatus = "pending" | "running" | "passed" | "failed" | "skipped";

interface VerificationStep {
  id: StepId;
  label: string;
  status: StepStatus;
  message?: string;        // Human-readable result (e.g., "Chain depth: 6, root: aws.nitro-enclaves")
  durationMs?: number;     // Time taken for this step
}

interface ParsedAttestation {
  moduleId: string;        // Enclave instance ID (e.g., "i-076...aef-enc019...")
  timestamp: number;       // Unix timestamp (ms)
  digest: string;          // Hash algorithm ("SHA384")
  pcrs: Record<number, string>;  // PCR0-15 as hex strings
  userData: Record<string, unknown> | null;  // Application data (job_id, script_hash, etc.)
  nonce: Uint8Array | null;
  publicKey: Uint8Array | null;
  certificate: Uint8Array;   // DER-encoded enclave certificate
  cabundle: Uint8Array[];    // Certificate chain to AWS root
  rawProtected: Uint8Array;  // COSE protected header
  rawPayload: Uint8Array;    // COSE payload (for signature verification)
  rawSignature: Uint8Array;  // ECDSA P-384 signature
}

interface CertChainInfo {
  depth: number;           // Total chain length (typically 6)
  root: { cn: string; fingerprint: string };  // AWS root cert info
  intermediateCount: number;
  endEntity: { cn: string; validFrom: string; validTo: string };  // Enclave cert
}

interface VerificationOptions {
  expectedPcrs?: { pcr0?: string; pcr1?: string; pcr2?: string };
  expectedOutputHash?: string;
  allowExpired?: boolean;          // For historical attestations (~3hr cert lifetime)
  customRootCertPem?: string;      // For local/dev attestation (replaces AWS root)
  onStepUpdate?: (stepId: StepId, update: Partial<VerificationStep>) => void;
}
```

## Use in Your Own Project

This package works with **any** AWS Nitro Enclave attestation document, not just Epsilon.

**Build a verification UI:**
```typescript
import { verifyAttestation } from "@epsilon-data/nitro-verify";

// In a React component
const [result, setResult] = useState(null);
const verify = async (base64Doc) => {
  const r = await verifyAttestation(base64Doc, {
    allowExpired: true,
    onStepUpdate: (id, update) => {
      // Update UI progress bar per step
    },
  });
  setResult(r);
};
```

**Verify in a CI pipeline:**
```typescript
import { verifyAttestation } from "@epsilon-data/nitro-verify";

const result = await verifyAttestation(attestationFromAPI, {
  expectedPcrs: { pcr0: PUBLISHED_PCR0 },
});
if (!result.valid) throw new Error(`Attestation failed: ${result.error}`);
```

**Extract attestation metadata without full verification:**
```typescript
import { verifyAttestation } from "@epsilon-data/nitro-verify";

const result = await verifyAttestation(base64Doc, { allowExpired: true });
const { moduleId, timestamp, pcrs, userData } = result.attestation;
console.log(`Job ${userData.job_id} ran at ${new Date(timestamp).toISOString()}`);
```

## Testing

```bash
npm test
```

Tests use a real AWS Nitro Enclave attestation document from production, verifying parsing, certificate chain, signature, and PCR matching.

## Requirements

- **Browser**: Any browser with [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (all modern browsers)
- **Node.js**: 18+ (WebCrypto available globally)
- **No native dependencies** — pure JavaScript/TypeScript, runs anywhere WebCrypto is available

## Dependencies

- [`cborg`](https://github.com/rvagg/cborg) — CBOR encoding/decoding
- [`@peculiar/x509`](https://github.com/PeculiarVentures/x509) — X.509 certificate parsing

## License

MIT
