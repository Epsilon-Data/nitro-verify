/**
 * Step 1: CBOR/COSE_Sign1 parsing and syntactical validation.
 *
 * Implements AWS Nitro Enclave attestation document parsing per:
 * https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md
 */
import * as cborg from "cborg";
import { base64ToUint8Array, uint8ArrayToHex } from "./utils";
import type { ParsedAttestation } from "./types";

// AWS Nitro attestation constants per AWS spec
const VALID_PCR_LENGTHS = new Set([32, 48, 64]); // SHA256, SHA384, SHA512
const MAX_PCR_INDEX = 31;
const REQUIRED_DIGEST = "SHA384";
const MAX_PAYLOAD_SIZE = 16384; // 16KB
const MAX_USER_DATA_SIZE = 512;
const MAX_NONCE_SIZE = 512;
const MAX_PUBLIC_KEY_SIZE = 1024;

/**
 * Parse and validate a base64-encoded COSE_Sign1 attestation document.
 *
 * Performs full syntactical validation per AWS specification:
 * - COSE_Sign1 structure (tag 18, 4-element array)
 * - Protected header algorithm must be ES384 (-35)
 * - Signature length must be 96 bytes
 * - All required fields present and correctly typed
 * - Size constraints on all fields
 */
export function parseCoseSign1(attestationDocBase64: string): ParsedAttestation {
  // Base64 decode
  let rawBytes: Uint8Array;
  try {
    rawBytes = base64ToUint8Array(attestationDocBase64);
  } catch (e) {
    throw new Error(`Invalid base64: ${e}`);
  }

  // CBOR decode with COSE_Sign1 tag 18 support
  // cborg tags option is an array where index = tag number
  let coseArray: unknown[];
  try {
    const tags: ((inner: unknown) => unknown)[] = [];
    tags[18] = (value: unknown) => value; // COSE_Sign1 tag
    const decoded = cborg.decode(rawBytes, { tags });

    if (Array.isArray(decoded)) {
      coseArray = decoded;
    } else {
      throw new Error(
        `Invalid COSE structure type: ${typeof decoded}`
      );
    }
  } catch (e) {
    if (e instanceof Error && e.message.startsWith("Invalid COSE")) throw e;
    throw new Error(`Invalid CBOR: ${e}`);
  }

  // COSE_Sign1 must have exactly 4 elements: [protected, unprotected, payload, signature]
  if (coseArray.length !== 4) {
    throw new Error(
      `COSE_Sign1 must have 4 elements, got ${coseArray.length}`
    );
  }

  const [protectedHeader, , payload, signature] = coseArray;

  // Validate protected header
  if (!(protectedHeader instanceof Uint8Array)) {
    throw new Error("Protected header must be bytes");
  }

  try {
    // COSE protected header uses integer keys, so decode with useMaps
    const protectedMap = protectedHeader.length > 0
      ? (cborg.decode(protectedHeader, { useMaps: true }) as Map<number, unknown>)
      : new Map<number, unknown>();
    const alg = protectedMap.get(1);
    if (alg !== -35) {
      // -35 = ES384 per COSE spec
      throw new Error(
        `Expected algorithm ES384 (-35), got ${alg}`
      );
    }
  } catch (e) {
    if (e instanceof Error && e.message.startsWith("Expected algorithm")) throw e;
    throw new Error(`Invalid protected header: ${e}`);
  }

  // Validate signature
  if (!(signature instanceof Uint8Array)) {
    throw new Error("Signature must be bytes");
  }
  if (signature.length !== 96) {
    // ES384 = 48 bytes r + 48 bytes s
    throw new Error(
      `Invalid signature length: ${signature.length}, expected 96 for ES384`
    );
  }

  // Validate payload
  if (!(payload instanceof Uint8Array)) {
    throw new Error("Payload must be bytes");
  }
  if (payload.length === 0) {
    throw new Error("Payload cannot be empty");
  }
  if (payload.length > MAX_PAYLOAD_SIZE) {
    throw new Error(
      `Payload exceeds max size: ${payload.length} > ${MAX_PAYLOAD_SIZE}`
    );
  }

  // Parse payload CBOR — use useMaps for integer-keyed PCR map
  let payloadMap: Map<string, unknown>;
  try {
    payloadMap = cborg.decode(payload, { useMaps: true }) as Map<string, unknown>;
  } catch (e) {
    throw new Error(`Invalid payload CBOR: ${e}`);
  }

  // Convert Map to plain object for validation (string keys are top-level)
  const payloadData: Record<string, unknown> = {};
  for (const [k, v] of payloadMap.entries()) {
    payloadData[String(k)] = v;
  }

  // Validate required fields per AWS spec
  validateAttestationFields(payloadData);

  // Extract PCRs: convert bytes to hex strings
  // pcrs is a Map<number, Uint8Array> from useMaps decode
  const pcrsRaw = payloadData["pcrs"] as Map<number, Uint8Array>;
  const pcrs: Record<number, string> = {};

  if (pcrsRaw instanceof Map) {
    pcrsRaw.forEach((value, key) => {
      pcrs[Number(key)] = value instanceof Uint8Array ? uint8ArrayToHex(value) : String(value);
    });
  } else {
    for (const [key, value] of Object.entries(pcrsRaw as Record<string, Uint8Array>)) {
      pcrs[Number(key)] = value instanceof Uint8Array ? uint8ArrayToHex(value) : String(value);
    }
  }

  // Parse user_data as JSON if possible
  const userDataRaw = payloadData["user_data"] as Uint8Array | null | undefined;
  let userData: Record<string, unknown> | null = null;
  if (userDataRaw && userDataRaw.length > 0) {
    try {
      const text = new TextDecoder().decode(userDataRaw);
      userData = JSON.parse(text) as Record<string, unknown>;
    } catch {
      // Not JSON — store as hex
      userData = { raw: uint8ArrayToHex(userDataRaw) };
    }
  }

  return {
    moduleId: payloadData["module_id"] as string,
    timestamp: payloadData["timestamp"] as number,
    digest: payloadData["digest"] as string,
    pcrs,
    certificate: payloadData["certificate"] as Uint8Array,
    cabundle: payloadData["cabundle"] as Uint8Array[],
    userData,
    nonce: (payloadData["nonce"] as Uint8Array) ?? null,
    publicKey: (payloadData["public_key"] as Uint8Array) ?? null,
    rawProtected: protectedHeader,
    rawPayload: payload,
    rawSignature: signature,
  };
}

/**
 * Validate attestation document fields per AWS specification.
 *
 * Required: module_id, digest, timestamp, pcrs, certificate, cabundle
 * Optional: public_key, user_data, nonce (with size constraints)
 */
function validateAttestationFields(payload: Record<string, unknown>): void {
  // module_id: non-empty text string
  const moduleId = payload["module_id"];
  if (!moduleId || typeof moduleId !== "string") {
    throw new Error("module_id must be a non-empty string");
  }

  // digest: must be "SHA384"
  const digest = payload["digest"];
  if (digest !== REQUIRED_DIGEST) {
    throw new Error(`digest must be '${REQUIRED_DIGEST}', got '${digest}'`);
  }

  // timestamp: positive integer
  const timestamp = payload["timestamp"];
  if (typeof timestamp !== "number" || timestamp <= 0) {
    throw new Error("timestamp must be a positive integer");
  }

  // pcrs: map with 1-32 entries
  const pcrs = payload["pcrs"];
  const pcrsIsMap = pcrs instanceof Map;
  const pcrsIsObj = pcrs !== null && typeof pcrs === "object" && !Array.isArray(pcrs);

  if (!pcrsIsMap && !pcrsIsObj) {
    throw new Error("pcrs must be a non-empty map");
  }

  const pcrsEntries: [unknown, unknown][] = pcrsIsMap
    ? Array.from((pcrs as Map<unknown, unknown>).entries())
    : Object.entries(pcrs as Record<string, unknown>).map(([k, v]) => [Number(k), v]);

  if (pcrsEntries.length === 0) {
    throw new Error("pcrs must be a non-empty map");
  }
  if (pcrsEntries.length > MAX_PCR_INDEX + 1) {
    throw new Error(`pcrs cannot have more than ${MAX_PCR_INDEX + 1} entries`);
  }

  for (const [idx, value] of pcrsEntries) {
    const i = Number(idx);
    if (isNaN(i) || i < 0 || i > MAX_PCR_INDEX) {
      throw new Error(`Invalid PCR index: ${idx}`);
    }
    if (!(value instanceof Uint8Array) || !VALID_PCR_LENGTHS.has(value.length)) {
      throw new Error(
        `PCR${i} must be 32, 48, or 64 bytes`
      );
    }
  }

  // certificate: DER-encoded bytes
  const certificate = payload["certificate"];
  if (!(certificate instanceof Uint8Array) || certificate.length === 0) {
    throw new Error("certificate must be non-empty bytes");
  }

  // cabundle: non-empty array
  const cabundle = payload["cabundle"];
  if (!Array.isArray(cabundle) || cabundle.length === 0) {
    throw new Error("cabundle must be a non-empty array");
  }

  // Optional fields with size validation per AWS spec
  const userData = payload["user_data"];
  if (userData != null) {
    if (!(userData instanceof Uint8Array)) {
      throw new Error("user_data must be bytes");
    }
    if (userData.length > MAX_USER_DATA_SIZE) {
      throw new Error(`user_data cannot exceed ${MAX_USER_DATA_SIZE} bytes`);
    }
  }

  const nonce = payload["nonce"];
  if (nonce != null) {
    if (!(nonce instanceof Uint8Array)) {
      throw new Error("nonce must be bytes");
    }
    if (nonce.length > MAX_NONCE_SIZE) {
      throw new Error(`nonce cannot exceed ${MAX_NONCE_SIZE} bytes`);
    }
  }

  const publicKey = payload["public_key"];
  if (publicKey != null) {
    if (!(publicKey instanceof Uint8Array)) {
      throw new Error("public_key must be bytes");
    }
    if (publicKey.length > MAX_PUBLIC_KEY_SIZE) {
      throw new Error(`public_key cannot exceed ${MAX_PUBLIC_KEY_SIZE} bytes`);
    }
  }
}
