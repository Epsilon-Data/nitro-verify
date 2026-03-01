/**
 * CLI for @aspect-data/nitro-verify
 *
 * Usage:
 *   nitro-verify <attestation.b64>                          # verify from file
 *   nitro-verify <attestation.b64> --pcr0 <hex> --pcr1 <hex> --pcr2 <hex>  # with PCR check
 *   nitro-verify <attestation.b64> --output-hash <hex>      # with output hash check
 *   echo <base64> | nitro-verify --stdin                    # verify from stdin
 *   nitro-verify --parse <attestation.b64>                  # parse only, print fields
 */
import * as fs from "node:fs";
import { verifyAttestation } from "./verify";
import { parseCoseSign1 } from "./parse";

const BOLD = "\x1b[1m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

function isAllZeroPcr(hex: string): boolean {
  return hex.replace(/0/g, "") === "";
}

function printPcrValues(pcrs: Record<number, string>) {
  for (const [idx, hex] of Object.entries(pcrs)) {
    if (!isAllZeroPcr(hex)) {
      console.log(`  ${CYAN}PCR${idx}${RESET}  ${hex}`);
    }
  }
}

function printUserData(userData: Record<string, unknown> | null) {
  if (!userData) return;
  console.log(`\n  ${BOLD}User Data${RESET}`);
  for (const [key, value] of Object.entries(userData)) {
    const val = typeof value === "object" ? JSON.stringify(value) : String(value);
    console.log(`  ${CYAN}${key}${RESET}  ${val.length > 80 ? val.substring(0, 80) + "..." : val}`);
  }
}

function printUsage() {
  console.log(`
${BOLD}@aspect-data/nitro-verify${RESET} — AWS Nitro Enclave Attestation Verifier

${BOLD}USAGE${RESET}
  nitro-verify <file.b64>              Verify attestation from file
  nitro-verify --stdin                 Verify attestation from stdin
  nitro-verify --parse <file.b64>      Parse and display attestation fields

${BOLD}OPTIONS${RESET}
  --pcr0 <hex>          Expected PCR0 value (enclave image hash)
  --pcr1 <hex>          Expected PCR1 value (kernel hash)
  --pcr2 <hex>          Expected PCR2 value (application hash)
  --output-hash <hex>   Expected output hash from user_data
  --allow-expired       Skip certificate date validation (for historical attestations)
  --stdin               Read attestation document from stdin
  --parse               Parse only mode (no cryptographic verification)
  --json                Output results as JSON
  -h, --help            Show this help

${BOLD}EXAMPLES${RESET}
  ${DIM}# Verify a downloaded attestation document${RESET}
  nitro-verify attestation.b64

  ${DIM}# Verify with expected PCR values from nitro-cli describe-enclaves${RESET}
  nitro-verify attestation.b64 \\
    --pcr0 6165855369654a587bdad59fa532f430d7defa38ecf57eeac6d29c7e87a32b621891862d04fb64423f6bb1e1626fc026

  ${DIM}# Pipe from curl or other tools${RESET}
  cat attestation.b64 | nitro-verify --stdin

  ${DIM}# Verify a historical attestation (expired certs)${RESET}
  nitro-verify attestation.b64 --allow-expired

  ${DIM}# Parse and inspect attestation fields${RESET}
  nitro-verify --parse attestation.b64
`);
}

function parseArgs(argv: string[]) {
  const args = argv.slice(2);
  const opts: {
    file?: string;
    stdin: boolean;
    parseOnly: boolean;
    json: boolean;
    allowExpired: boolean;
    pcr0?: string;
    pcr1?: string;
    pcr2?: string;
    outputHash?: string;
    help: boolean;
  } = { stdin: false, parseOnly: false, json: false, allowExpired: false, help: false };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-h" || arg === "--help") {
      opts.help = true;
    } else if (arg === "--stdin") {
      opts.stdin = true;
    } else if (arg === "--parse") {
      opts.parseOnly = true;
    } else if (arg === "--json") {
      opts.json = true;
    } else if (arg === "--allow-expired") {
      opts.allowExpired = true;
    } else if (arg === "--pcr0" && i + 1 < args.length) {
      opts.pcr0 = args[++i];
    } else if (arg === "--pcr1" && i + 1 < args.length) {
      opts.pcr1 = args[++i];
    } else if (arg === "--pcr2" && i + 1 < args.length) {
      opts.pcr2 = args[++i];
    } else if (arg === "--output-hash" && i + 1 < args.length) {
      opts.outputHash = args[++i];
    } else if (!arg.startsWith("-") && !opts.file) {
      opts.file = arg;
    }
  }

  return opts;
}

async function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data.trim()));
    process.stdin.on("error", reject);
  });
}

async function getAttestationDoc(opts: ReturnType<typeof parseArgs>): Promise<string> {
  if (opts.stdin) {
    return readStdin();
  }
  if (opts.file) {
    if (!fs.existsSync(opts.file)) {
      console.error(`${RED}Error:${RESET} File not found: ${opts.file}`);
      process.exit(1);
    }
    return fs.readFileSync(opts.file, "utf-8").trim();
  }
  console.error(`${RED}Error:${RESET} No attestation document provided. Use a file path or --stdin.`);
  console.error(`Run ${BOLD}nitro-verify --help${RESET} for usage.`);
  process.exit(1);
}

function printParseResult(doc: string) {
  console.log(`\n${BOLD}Parsing attestation document...${RESET}\n`);
  const att = parseCoseSign1(doc);

  console.log(`  ${CYAN}Module ID${RESET}      ${att.moduleId}`);
  console.log(`  ${CYAN}Digest${RESET}         ${att.digest}`);
  console.log(`  ${CYAN}Timestamp${RESET}      ${new Date(att.timestamp).toISOString()}`);
  console.log(`  ${CYAN}Certificate${RESET}    ${att.certificate.length} bytes`);
  console.log(`  ${CYAN}CA Bundle${RESET}      ${att.cabundle.length} certificates`);
  console.log(`  ${CYAN}Signature${RESET}      ${att.rawSignature.length} bytes`);
  console.log(`  ${CYAN}Nonce${RESET}          ${att.nonce ? `${att.nonce.length} bytes` : "(none)"}`);

  console.log(`\n  ${BOLD}PCR Values${RESET}`);
  printPcrValues(att.pcrs);
  printUserData(att.userData);

  console.log();
}

async function runVerification(doc: string, opts: ReturnType<typeof parseArgs>) {
  const expectedPcrs =
    opts.pcr0 || opts.pcr1 || opts.pcr2
      ? { pcr0: opts.pcr0, pcr1: opts.pcr1, pcr2: opts.pcr2 }
      : undefined;

  if (!opts.json) {
    console.log(`\n${BOLD}@aspect-data/nitro-verify${RESET} — AWS Nitro Enclave Attestation Verifier\n`);
    if (opts.allowExpired) {
      console.log(`  ${YELLOW}! Certificate date validation skipped (--allow-expired)${RESET}\n`);
    }
  }

  const result = await verifyAttestation(doc, {
    expectedPcrs,
    expectedOutputHash: opts.outputHash,
    allowExpired: opts.allowExpired,
    onStepUpdate: (stepId, update) => {
      if (opts.json) return;
      if (update.status === "passed") {
        console.log(`  ${GREEN}\u2713${RESET} ${update.message || stepId}${update.durationMs !== undefined ? ` ${DIM}(${update.durationMs}ms)${RESET}` : ""}`);
      } else if (update.status === "failed") {
        console.log(`  ${RED}\u2717${RESET} ${update.message || stepId}${update.durationMs !== undefined ? ` ${DIM}(${update.durationMs}ms)${RESET}` : ""}`);
      } else if (update.status === "skipped") {
        console.log(`  ${DIM}- ${stepId}: skipped${RESET}`);
      }
    },
  });

  if (opts.json) {
    // Strip raw bytes from JSON output for readability
    const jsonResult = {
      ...result,
      attestation: result.attestation
        ? {
            moduleId: result.attestation.moduleId,
            timestamp: result.attestation.timestamp,
            digest: result.attestation.digest,
            pcrs: result.attestation.pcrs,
            userData: result.attestation.userData,
          }
        : null,
    };
    console.log(JSON.stringify(jsonResult, null, 2));
    process.exit(result.valid ? 0 : 1);
  }

  // Print cert chain info
  if (result.certChainInfo) {
    console.log(`\n  ${BOLD}Certificate Chain${RESET}`);
    console.log(`  ${CYAN}Root${RESET}           ${result.certChainInfo.root.cn}`);
    console.log(`  ${CYAN}Fingerprint${RESET}    ${result.certChainInfo.root.fingerprint}`);
    console.log(`  ${CYAN}Chain Depth${RESET}    ${result.certChainInfo.depth}`);
    console.log(`  ${CYAN}End Entity${RESET}     ${result.certChainInfo.endEntity.cn}`);
    console.log(`  ${CYAN}Valid${RESET}          ${result.certChainInfo.endEntity.validFrom} → ${result.certChainInfo.endEntity.validTo}`);
  }

  // Print PCR values from attestation
  if (result.attestation) {
    console.log(`\n  ${BOLD}PCR Values (from attestation)${RESET}`);
    printPcrValues(result.attestation.pcrs);
    printUserData(result.attestation.userData);
  }

  // Final verdict
  console.log();
  if (result.valid) {
    console.log(`  ${GREEN}${BOLD}\u2713 VERIFICATION PASSED${RESET} — All cryptographic checks succeeded.`);
    console.log(`  ${DIM}This attestation was produced by a genuine AWS Nitro Enclave.${RESET}`);
  } else {
    console.log(`  ${RED}${BOLD}\u2717 VERIFICATION FAILED${RESET}${result.error ? ` — ${result.error}` : ""}`);
  }
  console.log();

  process.exit(result.valid ? 0 : 1);
}

async function main() {
  const opts = parseArgs(process.argv);

  if (opts.help) {
    printUsage();
    process.exit(0);
  }

  if (!opts.file && !opts.stdin) {
    printUsage();
    process.exit(1);
  }

  const doc = await getAttestationDoc(opts);

  if (opts.parseOnly) {
    printParseResult(doc);
  } else {
    await runVerification(doc, opts);
  }
}

main().catch((e) => {
  console.error(`${RED}Error:${RESET}`, e.message || e);
  process.exit(1);
});
