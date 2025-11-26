#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');

// Configuration
const REPOSITORIES = [
  'card-service',
  'card-management-service',
  'debit-card-service',
  'onboarding-core',
  'credit-card-service',
  'card-settlement-service'
];

const WORKSPACE_ROOT = path.resolve(__dirname, '..');
const COMPROMISED_PACKAGES_CSV_URL = 'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv';

// Malicious files to scan for
const MALICIOUS_FILES = [
  'cloud.json',
  'contents.json',
  'environment.json',
  'truffleSecrets.json',
  'setup_bun.js',
  'bun_environment.js',
  'actionsSecrets.json'
];

// Scan results storage
const scanResults = {
  summary: {
    totalRepos: 0,
    reposScanned: 0,
    criticalFindings: 0,
    highFindings: 0,
    mediumFindings: 0,
    lowFindings: 0
  },
  repositories: {}
};

// Fetch CSV data from URL
function fetchCSV(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`Failed to fetch CSV: HTTP ${res.statusCode}`));
        return;
      }
      
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        resolve(data);
      });
    }).on('error', (error) => {
      reject(error);
    });
  });
}

// Parse CSV and convert to package format
function parseCSVToPackages(csvText) {
  const packages = {};
  const lines = csvText.trim().split('\n');
  
  // Skip header line
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    
    // Split by last comma to handle package names that might contain commas
    const lastCommaIndex = line.lastIndexOf(',');
    if (lastCommaIndex === -1) continue;
    
    const packageName = line.substring(0, lastCommaIndex).trim();
    const versionString = line.substring(lastCommaIndex + 1).trim();
    
    if (!packageName || !versionString) continue;
    
    // Parse versions - handle formats like "= 0.0.7" or "= 0.0.7 || = 0.0.8"
    const versions = versionString
      .split('||')
      .map(v => v.trim())
      .filter(v => v.startsWith('='))
      .map(v => v.substring(1).trim()) // Remove "=" prefix
      .filter(v => v.length > 0);
    
    if (versions.length > 0) {
      if (!packages[packageName]) {
        packages[packageName] = [];
      }
      // Add versions, avoiding duplicates
      for (const version of versions) {
        if (!packages[packageName].includes(version)) {
          packages[packageName].push(version);
        }
      }
    }
  }
  
  return packages;
}

// Load compromised packages database from CSV URL
async function loadCompromisedPackages() {
  try {
    console.log('Fetching compromised packages from GitHub...');
    const csvData = await fetchCSV(COMPROMISED_PACKAGES_CSV_URL);
    const packages = parseCSVToPackages(csvData);
    console.log(`Loaded ${Object.keys(packages).length} compromised packages`);
    return packages;
  } catch (error) {
    console.error(`Error loading compromised packages: ${error.message}`);
    return {};
  }
}

// Parse package.json
function parsePackageJson(repoPath) {
  const packageJsonPath = path.join(repoPath, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    return null;
  }
  
  try {
    const content = fs.readFileSync(packageJsonPath, 'utf8');
    return JSON.parse(content);
  } catch (error) {
    console.error(`Error parsing package.json in ${repoPath}: ${error.message}`);
    return null;
  }
}

// Parse yarn.lock to get exact versions
function parseYarnLock(repoPath) {
  const yarnLockPath = path.join(repoPath, 'yarn.lock');
  if (!fs.existsSync(yarnLockPath)) {
    return {};
  }
  
  const lockData = {};
  try {
    const content = fs.readFileSync(yarnLockPath, 'utf8');
    const lines = content.split('\n');
    
    let currentPackage = null;
    let currentVersion = null;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      // Match package declaration lines like: "@package/name@^1.0.0", "@package/name@^1.0.0":
      // Extract package name from the first entry
      if (line.match(/^"@?[^"]+"@[^"]+":$/)) {
        const match = line.match(/^"(@?[^"]+)"@/);
        if (match) {
          currentPackage = match[1];
          currentVersion = null;
        }
      } else if (line.startsWith('version "') && currentPackage) {
        const versionMatch = line.match(/version "([^"]+)"/);
        if (versionMatch) {
          currentVersion = versionMatch[1];
          if (!lockData[currentPackage]) {
            lockData[currentPackage] = [];
          }
          // Only add if not already present (avoid duplicates)
          if (!lockData[currentPackage].includes(currentVersion)) {
            lockData[currentPackage].push(currentVersion);
          }
        }
      } else if (line === '') {
        // Reset on empty line (new package section)
        if (i > 0 && lines[i - 1].trim().startsWith('integrity')) {
          currentPackage = null;
          currentVersion = null;
        }
      }
    }
  } catch (error) {
    console.error(`Error parsing yarn.lock in ${repoPath}: ${error.message}`);
  }
  
  return lockData;
}

// Check for compromised packages
function checkCompromisedPackages(packageJson, yarnLock, compromisedPackages) {
  const findings = [];
  
  if (!packageJson) return findings;
  
  const allDeps = {
    ...(packageJson.dependencies || {}),
    ...(packageJson.devDependencies || {})
  };
  
  for (const [pkgName, versionSpec] of Object.entries(allDeps)) {
    if (compromisedPackages[pkgName]) {
      const compromisedVersions = compromisedPackages[pkgName];
      
      // Check if it's an array of versions (compromised versions list)
      if (Array.isArray(compromisedVersions)) {
        // Get exact version from yarn.lock if available
        const exactVersions = yarnLock[pkgName] || [];
        
        for (const exactVersion of exactVersions) {
          if (compromisedVersions.includes(exactVersion)) {
            findings.push({
              type: 'compromised_package',
              severity: 'CRITICAL',
              package: pkgName,
              version: exactVersion,
              versionSpec: versionSpec,
              source: 'yarn.lock'
            });
          }
        }
        
        // Also check if version spec matches any compromised version
        for (const compromisedVersion of compromisedVersions) {
          if (versionSpec.includes(compromisedVersion) || versionSpec === compromisedVersion) {
            findings.push({
              type: 'compromised_package',
              severity: 'CRITICAL',
              package: pkgName,
              version: compromisedVersion,
              versionSpec: versionSpec,
              source: 'package.json'
            });
          }
        }
      }
    }
  }
  
  return findings;
}

// Scan for malicious files
function scanMaliciousFiles(repoPath) {
  const findings = [];
  
  function scanDirectory(dir, depth = 0) {
    // Limit depth to avoid scanning too deep (e.g., node_modules)
    if (depth > 10) return;
    
    if (!fs.existsSync(dir)) return;
    
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        // Skip node_modules, .git, and other common directories
        if (entry.name === 'node_modules' || entry.name === '.git' || 
            entry.name === 'dist' || entry.name === 'build') {
          continue;
        }
        
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          scanDirectory(fullPath, depth + 1);
        } else if (entry.isFile()) {
          if (MALICIOUS_FILES.includes(entry.name)) {
            findings.push({
              type: 'malicious_file',
              severity: 'CRITICAL',
              file: path.relative(repoPath, fullPath),
              fullPath: fullPath
            });
          }
        }
      }
    } catch (error) {
      // Skip directories we can't read
    }
  }
  
  scanDirectory(repoPath);
  return findings;
}

// Check GitHub workflows
function checkGitHubWorkflows(repoPath) {
  const findings = [];
  const workflowsPath = path.join(repoPath, '.github', 'workflows');
  
  if (!fs.existsSync(workflowsPath)) {
    return findings;
  }
  
  try {
    const files = fs.readdirSync(workflowsPath);
    
    for (const file of files) {
      if (file.endsWith('.yml') || file.endsWith('.yaml')) {
        const filePath = path.join(workflowsPath, file);
        const content = fs.readFileSync(filePath, 'utf8');
        
        // Check for discussion.yaml with suspicious content
        if (file === 'discussion.yaml' || file === 'discussion.yml') {
          if (content.includes('self-hosted') && 
              (content.includes('discussion:') || content.includes('discussion'))) {
            findings.push({
              type: 'suspicious_workflow',
              severity: 'CRITICAL',
              file: `.github/workflows/${file}`,
              reason: 'Discussion workflow with self-hosted runner (potential backdoor)'
            });
          }
        }
        
        // Check for formatter workflows with secret exfiltration
        if (file.match(/^formatter.*\.(yml|yaml)$/)) {
          if (content.includes('${{ toJSON(secrets)}}') || 
              content.includes('toJSON(secrets)') ||
              content.includes('actionsSecrets')) {
            findings.push({
              type: 'suspicious_workflow',
              severity: 'CRITICAL',
              file: `.github/workflows/${file}`,
              reason: 'Formatter workflow with secret exfiltration pattern'
            });
          }
        }
        
        // Check for SHA1HULUD runner
        if (content.includes('SHA1HULUD') || content.includes('SHA1-HULUD')) {
          findings.push({
            type: 'suspicious_workflow',
            severity: 'CRITICAL',
            file: `.github/workflows/${file}`,
            reason: 'Workflow references SHA1HULUD runner name'
          });
        }
        
        // Check for self-hosted runner with suspicious patterns
        if (content.includes('runs-on: self-hosted') && 
            (content.includes('github.event.discussion') || 
             content.includes('RUNNER_TRACKING_ID'))) {
          findings.push({
            type: 'suspicious_workflow',
            severity: 'HIGH',
            file: `.github/workflows/${file}`,
            reason: 'Self-hosted runner with discussion event handler'
          });
        }
      }
    }
  } catch (error) {
    console.error(`Error checking workflows in ${repoPath}: ${error.message}`);
  }
  
  return findings;
}

// Check preinstall scripts
function checkPreinstallScripts(packageJson) {
  const findings = [];
  
  if (!packageJson || !packageJson.scripts) {
    return findings;
  }
  
  const preinstallScript = packageJson.scripts.preinstall;
  if (preinstallScript) {
    // Check for suspicious patterns
    const suspiciousPatterns = [
      /curl.*github/i,
      /wget.*github/i,
      /eval/i,
      /exec/i,
      /require\(['"]https?:/i,
      /fetch\(/i,
      /axios\(/i,
      /\.github/i,
      /octokit/i,
      /github\.com/i
    ];
    
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(preinstallScript)) {
        findings.push({
          type: 'suspicious_preinstall',
          severity: 'HIGH',
          script: preinstallScript,
          reason: `Preinstall script contains suspicious pattern: ${pattern}`
        });
        break;
      }
    }
  }
  
  return findings;
}

// Scan a single repository
async function scanRepository(repoName, compromisedPackages) {
  const repoPath = path.join(WORKSPACE_ROOT, repoName);
  
  if (!fs.existsSync(repoPath)) {
    console.log(`Repository ${repoName} not found at ${repoPath}`);
    return null;
  }
  
  console.log(`Scanning ${repoName}...`);
  
  const repoResults = {
    name: repoName,
    path: repoPath,
    findings: [],
    errors: []
  };
  
  // Parse package files
  const packageJson = parsePackageJson(repoPath);
  const yarnLock = parseYarnLock(repoPath);
  
  // Check for compromised packages
  const packageFindings = checkCompromisedPackages(packageJson, yarnLock, compromisedPackages);
  repoResults.findings.push(...packageFindings);
  
  // Scan for malicious files
  const fileFindings = scanMaliciousFiles(repoPath);
  repoResults.findings.push(...fileFindings);
  
  // Check GitHub workflows
  const workflowFindings = checkGitHubWorkflows(repoPath);
  repoResults.findings.push(...workflowFindings);
  
  // Check preinstall scripts
  const preinstallFindings = checkPreinstallScripts(packageJson);
  repoResults.findings.push(...preinstallFindings);
  
  // Update summary
  for (const finding of repoResults.findings) {
    switch (finding.severity) {
      case 'CRITICAL':
        scanResults.summary.criticalFindings++;
        break;
      case 'HIGH':
        scanResults.summary.highFindings++;
        break;
      case 'MEDIUM':
        scanResults.summary.mediumFindings++;
        break;
      case 'LOW':
        scanResults.summary.lowFindings++;
        break;
    }
  }
  
  return repoResults;
}

// Generate markdown report
function generateReport() {
  const reportPath = path.join(__dirname, 'shai-hulud-scan-report.md');
  let report = `# Shai-Hulud 2.0 Security Scan Report\n\n`;
  report += `**Scan Date:** ${new Date().toISOString()}\n\n`;
  report += `**Repositories Scanned:** ${scanResults.summary.reposScanned}\n\n`;
  
  // Executive Summary
  report += `## Executive Summary\n\n`;
  const totalFindings = scanResults.summary.criticalFindings + 
                        scanResults.summary.highFindings + 
                        scanResults.summary.mediumFindings + 
                        scanResults.summary.lowFindings;
  
  report += `| Severity | Count |\n`;
  report += `|----------|-------|\n`;
  report += `| **CRITICAL** | ${scanResults.summary.criticalFindings} |\n`;
  report += `| **HIGH** | ${scanResults.summary.highFindings} |\n`;
  report += `| **MEDIUM** | ${scanResults.summary.mediumFindings} |\n`;
  report += `| **LOW** | ${scanResults.summary.lowFindings} |\n`;
  report += `| **TOTAL** | **${totalFindings}** |\n\n`;
  
  if (totalFindings === 0) {
    report += `✅ **No Shai-Hulud 2.0 attack indicators detected.**\n\n`;
  } else {
    report += `⚠️ **Security findings detected. Immediate action required.**\n\n`;
  }
  
  // Repository-by-Repository Breakdown
  report += `## Repository-by-Repository Breakdown\n\n`;
  
  for (const [repoName, repoData] of Object.entries(scanResults.repositories)) {
    if (!repoData) continue;
    
    const repoFindings = repoData.findings || [];
    report += `### ${repoName}\n\n`;
    report += `**Path:** \`${repoData.path}\`\n\n`;
    report += `**Total Findings:** ${repoFindings.length}\n\n`;
    
    if (repoFindings.length === 0) {
      report += `✅ No issues detected.\n\n`;
    } else {
      // Group findings by type
      const byType = {};
      for (const finding of repoFindings) {
        if (!byType[finding.type]) {
          byType[finding.type] = [];
        }
        byType[finding.type].push(finding);
      }
      
      for (const [type, findings] of Object.entries(byType)) {
        report += `#### ${type.replace(/_/g, ' ').toUpperCase()}\n\n`;
        for (const finding of findings) {
          report += `- **${finding.severity}**: `;
          if (finding.package) {
            report += `Package \`${finding.package}@${finding.version}\` (spec: ${finding.versionSpec})`;
          } else if (finding.file) {
            report += `File: \`${finding.file}\``;
          } else if (finding.script) {
            report += `Preinstall script: \`${finding.script}\``;
          }
          if (finding.reason) {
            report += ` - ${finding.reason}`;
          }
          report += `\n`;
        }
        report += `\n`;
      }
    }
    report += `---\n\n`;
  }
  
  // Detailed Findings Table
  report += `## Detailed Findings Table\n\n`;
  report += `| Repository | Type | Severity | Details |\n`;
  report += `|------------|------|----------|---------|\n`;
  
  for (const [repoName, repoData] of Object.entries(scanResults.repositories)) {
    if (!repoData) continue;
    
    for (const finding of (repoData.findings || [])) {
      let details = '';
      if (finding.package) {
        details = `${finding.package}@${finding.version}`;
      } else if (finding.file) {
        details = finding.file;
      } else if (finding.script) {
        details = finding.script.substring(0, 50) + '...';
      } else {
        details = finding.reason || 'N/A';
      }
      
      report += `| ${repoName} | ${finding.type} | ${finding.severity} | ${details} |\n`;
    }
  }
  
  report += `\n`;
  
  // Recommendations
  report += `## Recommendations\n\n`;
  
  if (totalFindings > 0) {
    report += `### Immediate Actions Required:\n\n`;
    report += `1. **Remove and replace compromised packages**: Update all compromised npm packages to safe versions\n`;
    report += `2. **Delete malicious files**: Remove any detected malicious files immediately\n`;
    report += `3. **Review and remove suspicious workflows**: Delete or review any flagged GitHub workflows\n`;
    report += `4. **Rotate all credentials**: Rotate GitHub tokens, AWS credentials, GCP credentials, and Azure credentials\n`;
    report += `5. **Audit CI/CD environments**: Check for unauthorized self-hosted runners\n`;
    report += `6. **Review preinstall scripts**: Remove or audit any suspicious preinstall scripts\n`;
    report += `7. **Check for exfiltrated data**: Review GitHub repositories for unauthorized data exposure\n\n`;
  } else {
    report += `✅ No immediate actions required. Continue monitoring for new threats.\n\n`;
  }
  
  report += `### Ongoing Security Practices:\n\n`;
  report += `- Regularly update dependencies and review security advisories\n`;
  report += `- Use dependency scanning tools in CI/CD pipelines\n`;
  report += `- Implement package signing and verification\n`;
  report += `- Monitor for suspicious activity in GitHub workflows\n`;
  report += `- Keep compromised packages database updated\n\n`;
  
  report += `---\n\n`;
  report += `*Report generated by Shai-Hulud 2.0 Security Scanner*\n`;
  
  fs.writeFileSync(reportPath, report);
  console.log(`\nReport generated: ${reportPath}`);
}

// Main execution
async function main() {
  console.log('Shai-Hulud 2.0 Security Scanner');
  console.log('================================\n');
  
  // Load compromised packages once for all repositories
  const compromisedPackages = await loadCompromisedPackages();
  
  scanResults.summary.totalRepos = REPOSITORIES.length;
  
  for (const repo of REPOSITORIES) {
    const result = await scanRepository(repo, compromisedPackages);
    if (result) {
      scanResults.repositories[repo] = result;
      scanResults.summary.reposScanned++;
    }
  }
  
  console.log(`\nScan complete. Scanned ${scanResults.summary.reposScanned} repositories.`);
  console.log(`Findings: ${scanResults.summary.criticalFindings} Critical, ${scanResults.summary.highFindings} High`);
  
  generateReport();
}

// Run if executed directly
if (require.main === module) {
  main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

module.exports = { scanRepository, loadCompromisedPackages };

