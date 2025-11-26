# Shai-Hulud 2.0 Security Scanner

A comprehensive security scanning tool to detect Shai-Hulud 2.0 supply chain attack indicators across your repositories.

## Overview

This scanner checks for:
- **Compromised npm packages** - Detects known malicious package versions from the Shai-Hulud 2.0 attack
- **Malicious files** - Scans for files created by the malware (cloud.json, contents.json, environment.json, truffleSecrets.json, setup_bun.js, bun_environment.js, actionsSecrets.json)
- **Suspicious GitHub workflows** - Identifies backdoor workflows and secret exfiltration patterns
- **Suspicious preinstall scripts** - Flags potentially malicious preinstall scripts in package.json

## Prerequisites

- Node.js (v14 or higher)
- Access to the repositories you want to scan

## Installation

No installation required. The scanner uses only Node.js built-in modules.

## Usage

### Basic Usage

Run the scanner from the security-scan directory:

```bash
cd security-scan
node shai-hulud-scan.js
```

Or from the workspace root:

```bash
node security-scan/shai-hulud-scan.js
```

### Make Executable (Optional)

```bash
chmod +x security-scan/shai-hulud-scan.js
./security-scan/shai-hulud-scan.js
```

## Scanned Repositories

The scanner automatically scans the following repositories:
- `card-service`
- `card-management-service`
- `debit-card-service`
- `onboarding-core`
- `credit-card-service`
- `card-settlement-service`

## Output

The scanner generates a detailed markdown report: `shai-hulud-scan-report.md`

### Report Sections

1. **Executive Summary** - Overview of findings by severity
2. **Repository-by-Repository Breakdown** - Detailed findings for each repository
3. **Detailed Findings Table** - Tabular view of all findings
4. **Recommendations** - Actionable security recommendations

### Severity Levels

- **CRITICAL** - Immediate action required (compromised packages, malicious files, backdoor workflows)
- **HIGH** - High priority (suspicious preinstall scripts, suspicious workflows)
- **MEDIUM** - Medium priority findings
- **LOW** - Low priority findings

## What Gets Scanned

### Package Dependencies
- Parses `package.json` for dependencies and devDependencies
- Parses `yarn.lock` to get exact installed versions
- Matches against compromised packages database

### Malicious Files
Scans for the following files anywhere in the repository:
- `cloud.json`
- `contents.json`
- `environment.json`
- `truffleSecrets.json`
- `setup_bun.js`
- `bun_environment.js`
- `actionsSecrets.json`

### GitHub Workflows
Checks `.github/workflows/` directory for:
- `discussion.yaml` with self-hosted runners (potential backdoor)
- `formatter_*.yml` files with secret exfiltration patterns
- Workflows referencing "SHA1HULUD" runner
- Self-hosted runners with suspicious event handlers

### Preinstall Scripts
Analyzes `package.json` scripts for suspicious patterns:
- Network requests (curl, wget, fetch, axios)
- GitHub API calls
- Eval/exec patterns
- External code execution

## Compromised Packages Database

The scanner uses `compromised-packages.json` which contains known compromised packages and versions from the Shai-Hulud 2.0 attack.

**Note:** This database contains a partial list. The full attack involved ~700 packages. Update this database regularly with the latest security advisories.

### Updating the Database

Edit `compromised-packages.json` to add new compromised packages:

```json
{
  "package-name": ["1.0.0", "1.0.1", "1.0.2"],
  "another-package": ["2.0.0"]
}
```

## Recommendations

If the scanner finds issues:

1. **Immediate Actions:**
   - Remove and replace compromised packages
   - Delete malicious files
   - Review and remove suspicious workflows
   - Rotate all credentials (GitHub, AWS, GCP, Azure)
   - Audit CI/CD environments
   - Review preinstall scripts

2. **Ongoing Security:**
   - Regularly update dependencies
   - Use dependency scanning in CI/CD
   - Implement package signing
   - Monitor GitHub workflows
   - Keep compromised packages database updated

## Example Output

```
Shai-Hulud 2.0 Security Scanner
================================

Scanning card-service...
Scanning card-management-service...
Scanning debit-card-service...
Scanning onboarding-core...
Scanning credit-card-service...
Scanning card-settlement-service...

Scan complete. Scanned 6 repositories.
Findings: 0 Critical, 0 High

Report generated: /path/to/security-scan/shai-hulud-scan-report.md
```

## Troubleshooting

### Repository Not Found
If a repository is not found, the scanner will skip it and continue with others.

### Permission Errors
Ensure you have read permissions for all directories you want to scan.

### Yarn Lock Parsing
The yarn.lock parser may not catch all edge cases. If you notice missing package versions, verify manually.

## References

- [Wiz Blog: Shai-Hulud 2.0 Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Shai-Hulud 2.0 Detector](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector)

## License

This scanner is provided as-is for security scanning purposes.

