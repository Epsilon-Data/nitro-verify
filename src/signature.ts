/**
 * Step 3: COSE_Sign1 signature verification per RFC 8152.
 *
 * AWS Nitro Enclaves use ES384 (ECDSA with P-384 and SHA-384).
 * The signature in the attestation document is in IEEE P1363 format (r||s),
 * which WebCrypto accepts natively — no DER conversion needed.
 *
 * Verification:
 * 1. Extract public key from the leaf certificate
 * 2. Build the Sig_structure per RFC 8152 Section 4.4
 * 3. Verify ECDSA signature over the Sig_structure
 */
import * as cborg from "cborg";
import * as x509 from "@peculiar/x509";
import { toArrayBuffer } from "./utils";

/**
 * Verify the COSE_Sign1 signature using the leaf certificate's public key.
 *
 * @param rawProtected - CBOR-encoded protected header bytes
 * @param rawPayload - CBOR-encoded attestation payload bytes
 * @param rawSignature - 96-byte ECDSA P1363 signature (r||s)
 * @param leafCertDer - DER-encoded leaf certificate
 * @returns true if signature is valid
 * @throws Error if verification fails
 */
export async function verifyCoseSignature(
  rawProtected: Uint8Array,
  rawPayload: Uint8Array,
  rawSignature: Uint8Array,
  leafCertDer: Uint8Array
): Promise<boolean> {
  // Load the leaf certificate and extract its public key as a CryptoKey
  const cert = new x509.X509Certificate(toArrayBuffer(leafCertDer));
  const cryptoKey = await cert.publicKey.export(
    { name: "ECDSA", namedCurve: "P-384" },
    ["verify"]
  );

  // Build Sig_structure per RFC 8152 Section 4.4:
  // Sig_structure = ["Signature1", body_protected, external_aad, payload]
  //
  // - "Signature1" — context string for COSE_Sign1
  // - body_protected — the raw protected header bytes
  // - external_aad — empty bytes (no external authenticated data)
  // - payload — the raw payload bytes
  const sigStructure = cborg.encode([
    "Signature1",
    rawProtected,
    new Uint8Array(0), // external_aad
    rawPayload,
  ]);

  // Verify using WebCrypto
  // WebCrypto ECDSA natively uses IEEE P1363 (r||s) format,
  // which is exactly what COSE provides — no DER conversion needed
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-384" },
    cryptoKey,
    toArrayBuffer(rawSignature),
    toArrayBuffer(sigStructure),
  );

  if (!valid) {
    throw new Error("COSE_Sign1 signature verification failed");
  }

  return true;
}
