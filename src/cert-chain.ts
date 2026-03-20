/**
 * Step 2: Certificate chain verification.
 *
 * Validates the complete certificate chain from the enclave leaf certificate
 * up to the AWS Nitro Enclaves root certificate (trust anchor).
 *
 * Verification per AWS specification:
 * - Root certificate fingerprint (SHA-256 of DER)
 * - Certificate validity periods
 * - Basic Constraints (CA flag, pathLenConstraint)
 * - Key Usage extensions (digitalSignature for leaf, keyCertSign for CAs)
 * - Signature chain: each cert signed by the next, up to root
 *
 * Uses @peculiar/x509 for X.509 parsing and WebCrypto for signature verification.
 */
import * as x509 from "@peculiar/x509";
import {
  AWS_ROOT_CERT_PEM,
  AWS_ROOT_CERT_FINGERPRINT,
  AWS_ROOT_CERT_CN,
} from "./aws-root-cert";
import { pemToDer, uint8ArrayToHex, extractCN, toArrayBuffer } from "./utils";
import type { CertChainInfo } from "./types";

// Cache root certificate parsing — the PEM is a compile-time constant,
// so we only need to decode, parse, and fingerprint it once.
let cachedRoot: {
  cert: x509.X509Certificate;
  cn: string;
  fingerprint: string;
} | null = null;

async function getRootCert() {
  if (cachedRoot) return cachedRoot;

  const rootDerBytes = pemToDer(AWS_ROOT_CERT_PEM);
  const cert = new x509.X509Certificate(toArrayBuffer(rootDerBytes));

  const rootHashBuf = await crypto.subtle.digest("SHA-256", cert.rawData);
  const fingerprint = uint8ArrayToHex(new Uint8Array(rootHashBuf));

  if (fingerprint.toLowerCase() !== AWS_ROOT_CERT_FINGERPRINT.toLowerCase()) {
    throw new Error(
      `AWS root certificate fingerprint mismatch: expected ${AWS_ROOT_CERT_FINGERPRINT}, got ${fingerprint}`
    );
  }

  const cn = extractCN(cert.subject);
  if (cn !== AWS_ROOT_CERT_CN) {
    throw new Error(
      `AWS root certificate CN mismatch: expected ${AWS_ROOT_CERT_CN}, got ${cn}`
    );
  }

  if (cert.subject !== cert.issuer) {
    throw new Error("AWS root certificate must be self-signed");
  }

  cachedRoot = { cert, cn, fingerprint };
  return cachedRoot;
}

/**
 * Verify the certificate chain from the attestation document to the AWS root.
 *
 * @returns CertChainInfo with chain metadata if valid
 * @throws Error if any verification step fails
 */
export async function verifyCertificateChain(
  leafCertDer: Uint8Array,
  cabundle: Uint8Array[],
  options?: { allowExpired?: boolean; customRootCertPem?: string }
): Promise<CertChainInfo> {
  let rootCert: x509.X509Certificate;
  let rootCN: string;
  let rootFingerprint: string;

  if (options?.customRootCertPem) {
    // DEV MODE: use custom root certificate instead of AWS root
    const rootDerBytes = pemToDer(options.customRootCertPem);
    rootCert = new x509.X509Certificate(toArrayBuffer(rootDerBytes));
    rootCN = extractCN(rootCert.subject);
    const rootHashBuf = await crypto.subtle.digest("SHA-256", rootCert.rawData);
    rootFingerprint = uint8ArrayToHex(new Uint8Array(rootHashBuf));
  } else {
    ({ cert: rootCert, cn: rootCN, fingerprint: rootFingerprint } = await getRootCert());
  }

  // Load leaf certificate
  const leafCert = new x509.X509Certificate(toArrayBuffer(leafCertDer));

  // Load all CA certificates from cabundle
  const caCerts = cabundle.map((der) => new x509.X509Certificate(toArrayBuffer(der)));

  // Build chain by matching issuer → subject (not array order!)
  const chain: x509.X509Certificate[] = [leafCert];
  let currentCert = leafCert;

  while (true) {
    const issuerName = currentCert.issuer;
    let issuerCert: x509.X509Certificate | null = null;

    for (const ca of caCerts) {
      if (ca.subject === issuerName) {
        issuerCert = ca;
        break;
      }
    }

    if (!issuerCert) break;

    chain.push(issuerCert);
    currentCert = issuerCert;

    // Stop if self-signed (reached a root in the bundle)
    if (currentCert.subject === currentCert.issuer) break;
  }

  const now = new Date();
  const skipDateCheck = options?.allowExpired === true;

  // Validate each certificate in the chain
  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i];
    const isLeaf = i === 0;

    // Check validity period (skip if allowExpired)
    if (!skipDateCheck) {
      if (cert.notBefore > now) {
        throw new Error(`Certificate ${i} not yet valid (notBefore: ${cert.notBefore.toISOString()})`);
      }
      if (cert.notAfter < now) {
        throw new Error(`Certificate ${i} has expired (notAfter: ${cert.notAfter.toISOString()})`);
      }
    }

    // Check Basic Constraints using typed getExtension overload
    const bc = cert.getExtension(x509.BasicConstraintsExtension);
    if (bc) {
      if (!isLeaf) {
        // Intermediate/CA certs must have CA=true
        if (!bc.ca) {
          throw new Error(`Certificate ${i} is not a CA but is in the chain`);
        }
        // Validate pathLenConstraint
        if (bc.pathLength !== undefined) {
          const caCertsBetween = i - 1;
          if (bc.pathLength < caCertsBetween) {
            throw new Error(
              `Certificate ${i} pathLenConstraint ${bc.pathLength} < ${caCertsBetween}`
            );
          }
        }
      }
    } else if (!isLeaf) {
      throw new Error(`Certificate ${i} missing Basic Constraints`);
    }

    // Check Key Usage using typed getExtension overload
    const ku = cert.getExtension(x509.KeyUsagesExtension);
    if (ku) {
      if (isLeaf) {
        if (!(ku.usages & x509.KeyUsageFlags.digitalSignature)) {
          throw new Error("Leaf certificate missing digitalSignature key usage");
        }
      } else {
        if (!(ku.usages & x509.KeyUsageFlags.keyCertSign)) {
          throw new Error(`Certificate ${i} missing keyCertSign key usage`);
        }
      }
    }
  }

  // Verify signatures up the chain using WebCrypto
  for (let i = 0; i < chain.length - 1; i++) {
    const cert = chain[i];
    const issuerCert = chain[i + 1];
    const valid = await verifyX509Signature(cert, issuerCert, skipDateCheck);
    if (!valid) {
      throw new Error(`Certificate ${i} signature verification failed`);
    }
  }

  // Verify last cert in chain is signed by root
  const lastCert = chain[chain.length - 1];
  const rootSigValid = await verifyX509Signature(lastCert, rootCert, skipDateCheck);
  if (!rootSigValid) {
    throw new Error("Root certificate signature verification failed");
  }

  // Verify root certificate validity (skip if allowExpired)
  if (!skipDateCheck) {
    if (rootCert.notBefore > now) {
      throw new Error("Root certificate not yet valid");
    }
    if (rootCert.notAfter < now) {
      throw new Error("Root certificate has expired");
    }
  }

  // Build chain info result
  const endEntity = chain[0];
  return {
    depth: chain.length + 1, // chain + root
    root: { cn: rootCN, fingerprint: rootFingerprint },
    intermediateCount: chain.length - 1, // everything between leaf and root
    endEntity: {
      cn: extractCN(endEntity.subject),
      validFrom: endEntity.notBefore.toISOString(),
      validTo: endEntity.notAfter.toISOString(),
    },
  };
}

/**
 * Verify an X.509 certificate signature using the issuer's public key.
 * Uses WebCrypto API for all cryptographic operations.
 */
async function verifyX509Signature(
  cert: x509.X509Certificate,
  issuerCert: x509.X509Certificate,
  skipDateCheck: boolean = false
): Promise<boolean> {
  try {
    const publicKey = await issuerCert.publicKey.export();
    if (skipDateCheck) {
      // Bypass @peculiar/x509 date validation by using WebCrypto directly
      return await rawSignatureVerify(cert, publicKey);
    }
    const valid = await cert.verify({ publicKey });
    return valid;
  } catch {
    return false;
  }
}

/**
 * Verify an X.509 certificate signature using WebCrypto directly,
 * bypassing @peculiar/x509 date validation.
 */
async function rawSignatureVerify(
  cert: x509.X509Certificate,
  issuerPublicKey: CryptoKey
): Promise<boolean> {
  try {
    // Extract TBS (to-be-signed) certificate and signature from the raw DER
    const rawData = new Uint8Array(cert.rawData);
    const { tbs, signature } = extractTbsAndSignature(rawData);

    // Determine algorithm from cert's signature algorithm
    const sigAlg = cert.signatureAlgorithm;
    let algorithm: EcdsaParams | RsaHashedImportParams;

    if (sigAlg.name === "ECDSA" || sigAlg.hash) {
      const hashName = (sigAlg.hash as Algorithm)?.name || "SHA-384";
      algorithm = { name: "ECDSA", hash: hashName };
    } else {
      algorithm = { name: "ECDSA", hash: "SHA-384" };
    }

    // X.509 uses DER-encoded ECDSA signatures, but WebCrypto expects P1363 (r||s)
    const p1363Sig = derEcdsaToP1363(signature, 48); // 48 bytes per component for P-384

    return await crypto.subtle.verify(
      algorithm,
      issuerPublicKey,
      toArrayBuffer(p1363Sig),
      toArrayBuffer(tbs)
    );
  } catch {
    return false;
  }
}

/**
 * Extract TBS certificate and signature from DER-encoded X.509 certificate.
 * X.509 structure: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
 */
function extractTbsAndSignature(der: Uint8Array): { tbs: Uint8Array; signature: Uint8Array } {
  // Parse outer SEQUENCE
  let offset = 0;
  if (der[offset++] !== 0x30) throw new Error("Expected SEQUENCE");
  const { bytesRead } = readAsn1Length(der, offset);
  offset += bytesRead;

  // First element: TBS Certificate (SEQUENCE)
  const tbsStart = offset;
  if (der[offset++] !== 0x30) throw new Error("Expected TBS SEQUENCE");
  const { length: tbsContentLen, bytesRead: tbsLenBytes } = readAsn1Length(der, offset);
  offset += tbsLenBytes;
  const tbsEnd = offset + tbsContentLen;
  const tbs = der.slice(tbsStart, tbsEnd);
  offset = tbsEnd;

  // Second element: Signature Algorithm (SEQUENCE) — skip
  if (der[offset++] !== 0x30) throw new Error("Expected SignatureAlgorithm SEQUENCE");
  const { length: algLen, bytesRead: algLenBytes } = readAsn1Length(der, offset);
  offset += algLenBytes + algLen;

  // Third element: Signature Value (BIT STRING)
  if (der[offset++] !== 0x03) throw new Error("Expected BIT STRING");
  const { length: sigLen, bytesRead: sigLenBytes } = readAsn1Length(der, offset);
  offset += sigLenBytes;
  // BIT STRING has a leading byte for unused bits (should be 0) — skip it
  offset++;
  const signature = der.slice(offset, offset + sigLen - 1);

  return { tbs, signature };
}

/**
 * Convert DER-encoded ECDSA signature to IEEE P1363 format (r||s).
 * DER: SEQUENCE { INTEGER r, INTEGER s }
 * P1363: r (padded to componentLen) || s (padded to componentLen)
 */
function derEcdsaToP1363(derSig: Uint8Array, componentLen: number): Uint8Array {
  let offset = 0;

  // SEQUENCE tag
  if (derSig[offset++] !== 0x30) throw new Error("Expected SEQUENCE in ECDSA signature");
  const { bytesRead: seqLenBytes } = readAsn1Length(derSig, offset);
  offset += seqLenBytes;

  // INTEGER r
  if (derSig[offset++] !== 0x02) throw new Error("Expected INTEGER for r");
  const { length: rLen, bytesRead: rLenBytes } = readAsn1Length(derSig, offset);
  offset += rLenBytes;
  let r = derSig.slice(offset, offset + rLen);
  offset += rLen;

  // INTEGER s
  if (derSig[offset++] !== 0x02) throw new Error("Expected INTEGER for s");
  const { length: sLen, bytesRead: sLenBytes } = readAsn1Length(derSig, offset);
  offset += sLenBytes;
  let s = derSig.slice(offset, offset + sLen);

  // Strip leading zero padding (ASN.1 integers are signed, so high bit = padding)
  if (r.length > componentLen && r[0] === 0x00) r = r.slice(1);
  if (s.length > componentLen && s[0] === 0x00) s = s.slice(1);

  // Pad to componentLen
  const result = new Uint8Array(componentLen * 2);
  result.set(r, componentLen - r.length);
  result.set(s, componentLen * 2 - s.length);
  return result;
}

function readAsn1Length(data: Uint8Array, offset: number): { length: number; bytesRead: number } {
  const first = data[offset];
  if (first < 0x80) {
    return { length: first, bytesRead: 1 };
  }
  const numBytes = first & 0x7f;
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | data[offset + 1 + i];
  }
  return { length, bytesRead: 1 + numBytes };
}
