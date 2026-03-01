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

## Requirements

- **Browser**: Any browser with [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (all modern browsers)
- **Node.js**: 18+ (WebCrypto available globally)

## Dependencies

- [`cborg`](https://github.com/rvagg/cborg) — CBOR encoding/decoding
- [`@peculiar/x509`](https://github.com/nicolo-ribaudo/nicolo-ribaudo) — X.509 certificate parsing

## License

MIT
