# NPM Supply Chain Compromise Scanner

## Overview

This repository contains a tool for detecting and investigating the September 2025 NPM compromise that affected 25 popular packages through a sophisticated phishing attack. The malware targets cryptocurrency wallets by injecting malicious code that intercepts and redirects transactions.

## 🚀 v1.1.0 Final Draft

### ✅ Features Included:
- **API-Based Repository Scanning**: Full support for JFrog Artifactory and NPM Registry
- **Non authenticated scan** of know packages contained in a json file definistion
- **Deep Scan Capability**: Downloads and analyzes actual package contents for obfuscation patterns
- **Comprehensive Mode (-All)**: Scans extended package lists (45 packages for NPM Registry)
- **Cross-Platform Support**: Works on Windows, macOS, and Linux with PowerShell
- **Professional Reporting**: JSON and CSV export with HTML report generation
- **25 Malicious Package Detection**: Updated database including recent DuckDB compromise

### 🔧 Improvements from v1.0:
- Removed unreliable HTML scraping functionality for cleaner operation
- Enhanced deep scanning with actual package tarball downloads
- Improved error handling and cross-platform compatibility
- Updated malicious package database (18 → 25 packages)

## 🚨 Critical Information

**Incident Date**: September 8-9, 2025  
**Affected Packages**: 25 packages including debug, chalk, ansi-styles, duckdb  
**Attack Vector**: Browser-based cryptocurrency wallet hijacking  
**Phishing Domain**: npmjs.help (now taken down)  
**Latest Update**: Additional DuckDB packages compromised September 9, 2025

## Repository Contents

### 📁 Core Files

| File | Description |
|------|-------------|
| `Scan-NPMRepository.ps1` | Crimson7 NPM Security Scanner (PowerShell) |
| `Generate-HTMLReport.ps1` | Crimson7 HTML report generator with branded output |
| `malicious_packages.json` | Database of compromised packages and signatures |
| `NPM_Compromise_Timeline.md` | Complete incident timeline and analysis |
| `npm_threat_hunting_runbook_final.md` | KQL queries for Microsoft Sentinel |
| `NPM_Compromise_Executive_Summary_and_Report.md` | Executive report with findings |

## Installation & Setup

### Prerequisites
- PowerShell 5.1 or higher (Windows) or PowerShell Core 7+ (cross-platform)
- Network access to your NPM repository
- (Optional) API credentials for authenticated repository access

### Quick Start

1. Clone or download this repository:
```bash
git clone https://github.com/your-org/npm-compromise-scanner.git
cd npm-compromise-scanner
```

2. Ensure all three core files are in the same directory:
   - `Scan-NPMRepository.ps1`
   - `malicious_packages.json`
   - `NPM_Compromise_Timeline.md`

## Usage Guide

### 🔍 Scanning Methods

#### 1. Local Directory Scan
Scan your local projects for compromised packages:
```powershell
.\Scan-NPMRepository.ps1 -LocalPath "C:\Projects\YourApp"
```

With deep scanning for obfuscation patterns:
```powershell
.\Scan-NPMRepository.ps1 -LocalPath "C:\Projects\YourApp" -DeepScan
```

#### 3. Comprehensive Repository Scan
Scan extended package lists including popular packages (resource intensive):

**NPM Registry** - scans 45 packages (25 malicious + 20 popular):
```powershell
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://registry.npmjs.org/" -DeepScan -All
```

**JFrog Artifactory** - attempts to scan all packages in repository:
```powershell
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://artifactory.company.com/artifactory/npm-repo/" -DeepScan -All -ApiKey "YOUR_KEY"
```

#### 4. Remote Repository Scan (API-Based)

##### ⚠️ Important: Correct URL Format for JFrog

**Use the API or repository URL, NOT the UI URL:**

✅ **CORRECT - API URL (Recommended):**
```powershell
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://artifactory.company.com/artifactory/api/npm/npm-remote/"
```

✅ **CORRECT - Direct Repository URL:**
```powershell
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://artifactory.company.com/artifactory/npm-remote/"
```

❌ **WRONG - UI URL (This won't work):**
```powershell
# Don't use URLs with /ui/native/ - these are for browser access only
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://artifactory.company.com/ui/native/npm-remote/.npm"
```

##### How to Find Your Correct JFrog URL:

1. **From the UI URL in your browser:**
   - If you see: `https://artifactory.company.com/ui/native/npm-remote/.npm`
   - Use this: `https://artifactory.company.com/artifactory/api/npm/npm-remote/`

2. **General pattern:**
   - UI URL: `https://[server]/ui/native/[repo-name]/`
   - API URL: `https://[server]/artifactory/api/npm/[repo-name]/`
   - Direct URL: `https://[server]/artifactory/[repo-name]/`

3. **Test your URL:**
   ```bash
   # Test if the URL is correct (should return JSON)
   curl https://artifactory.company.com/artifactory/api/npm/npm-remote/
   ```

##### Examples with Authentication:
```powershell
# With API key (recommended for private repositories)
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://artifactory.company.com/artifactory/api/npm/npm-remote/" -ApiKey "AKCp5..."
```

#### 5. NPM Registry Scan
```powershell
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://registry.npmjs.org/"
```

#### 6. Combined Scan
Scan both local and remote simultaneously:
```powershell
.\Scan-NPMRepository.ps1 -LocalPath "." -RepositoryUrl "https://artifactory.company.com/artifactory/npm-repo/" -ApiKey "YOUR_KEY" -DeepScan
```

### 🔑 API Key Requirements

#### JFrog Artifactory
- **Public repositories**: API key is **NOT required**
- **Private repositories**: API key is **REQUIRED**
- **Benefits of using API key**:
  - Access to private packages
  - Higher rate limits
  - Detailed version information
  - Audit trail of scans

#### How to get JFrog API Key:
1. Log into your JFrog Artifactory instance
2. Click on your username (top right) → Edit Profile
3. Generate an API Key under "Authentication Settings"
4. Use with `-ApiKey` parameter

#### NPM Registry
- Public packages: No authentication needed
- Private packages: Use NPM token as API key

### ⚙️ Command Line Options

| Parameter | Required | Description | Example |
|-----------|----------|-------------|---------|
| `-LocalPath` | No | Local directory to scan | `-LocalPath "C:\Projects\MyApp"` |
| `-RepositoryUrl` | No | Remote repository URL | `-RepositoryUrl "https://registry.npmjs.org/"` |
| `-ApiKey` | No | Authentication key for private repos | `-ApiKey "AKCp5..."` |
| `-DeepScan` | No | Download and scan package contents | `-DeepScan` |
| `-All` | No | Scan extended package list including popular packages (⚠️ Resource intensive if used with API on Jfrog, scan all) | `-All` |
| `-OutputPath` | No | Custom output directory | `-OutputPath "C:\Reports"` |
| `-Verbose` | No | Detailed logging | `-Verbose` |

**⚠️ Important Notes:**
- `-All` parameter scans extended package lists: 
  - **JFrog Artifactory**: Attempts to scan every package in repository
  - **NPM Registry**: Scans 25 malicious + 20 popular packages (45 total)
- `-All` scanning is resource-intensive and may take several minutes for Jfrog
- `-DeepScan` downloads actual package files to analyze JavaScript content
- Combine `-All` and `-DeepScan` only for small repositories or targeted investigations  
- Use `-Verbose` for troubleshooting connection or parsing issues

### 📊 Output Formats

The scanner generates three types of output:

1. **Console Output** - Color-coded real-time results:
   - 🔴 **CRITICAL** (Red): Malicious packages found
   - 🟡 **SUSPICIOUS** (Yellow): Obfuscation patterns detected
   - 🔵 **CHECK** (Cyan): Manual review needed
   - 🟢 **CLEAN** (Green): No issues found

## Detection Capabilities

### ✅ What the Scanner Detects

1. **Exact Version Matching**
   - All 25 compromised packages with specific malicious versions
   - Original 18 packages: chalk@5.6.1, debug@4.4.2, ansi-styles@6.2.2
   - DuckDB packages: duckdb@1.3.3, @duckdb/node-api@1.3.3
   - Additional packages: @coveops/abi@2.0.1, prebid@10.9.1/10.9.2

2. **Obfuscation Patterns**
   - `const _0x112` signature pattern
   - Heavy hex-variable obfuscation (`_0x[0-9a-f]{4,}`)
   - Malware function names (`checkethereumw`, `stealthProxyControl`)

3. **Cryptocurrency Targeting**
   - Multiple wallet addresses in single file
   - Levenshtein distance algorithm (used for address swapping)
   - Wallet-related keywords and APIs

4. **Known Malicious Hashes**
   - SHA1: e9f9235f0fd79f5a7d099276ec6a9f8c5f0ddce9 (error-ex)
   - And 4 other confirmed malicious file hashes known on the public internet TLP-WHITE

### ⚠️ Limitations

- Cannot detect if malicious code has already been bundled into production builds
- May produce false positives for legitimate obfuscated code
- Requires file system access for deep scanning
- API rate limits may affect large repository scans

## Interpreting Results

### Status Levels

| Status | Meaning | Action Required |
|--------|---------|-----------------|
| **MALICIOUS** | Confirmed compromised package version | Immediate removal and remediation |
| **SUSPICIOUS** | Contains obfuscation patterns or wallet code | Manual review and testing |
| **CHECK_REQUIRED** | Unable to determine, parsing errors | Manual investigation |
| **CLEAN** | No indicators found | No action needed |

### Exit Codes (for CI/CD)

- `0` - No threats detected
- `1` - Suspicious packages found
- `2` - Malicious packages confirmed

## Remediation Steps

If malicious packages are detected:

1. **Immediate Actions**
   ```bash
   # Stop all builds
   # Remove node_modules
   rm -rf node_modules
   
   # Clear npm cache
   npm cache clean --force
   
   # Remove package-lock.json
   rm package-lock.json
   ```

2. **Clean Installation**
   ```bash
   # Update package.json to safe versions
   # Reinstall with exact versions
   npm install --save-exact
   
   # Audit for vulnerabilities
   npm audit fix
   ```

3. **Verification**
   ```powershell
   # Re-run scanner to confirm clean
   .\Scan-NPMRepository.ps1 -LocalPath "." -DeepScan
   ```

## Advanced Usage

### Custom Output Directory
```powershell
.\Scan-NPMRepository.ps1 -LocalPath "." -OutputPath "C:\SecurityReports"
```

### Scheduling Scans (Windows Task Scheduler)
```powershell
# Create scheduled task for daily scans
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\Scan-NPMRepository.ps1 -LocalPath C:\Projects -DeepScan"
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName "NPM Security Scan" -Action $action -Trigger $trigger
```

### Integration with CI/CD 
(not sure you'll be needing this without constantly updating the malicious_packages.json)
```yaml
# Azure DevOps Pipeline
- task: PowerShell@2
  displayName: 'NPM Security Scan'
  inputs:
    filePath: 'Scan-NPMRepository.ps1'
    arguments: '-LocalPath $(Build.SourcesDirectory) -DeepScan'
  continueOnError: false
```

## Threat Intelligence

### Compromised Packages List (25 Total)

#### Original Compromise (Sept 8, 2025)
| Package | Malicious Version | Downloads (millions) |
|---------|-------------------|---------------------|
| debug | 4.4.2 | 357.6 |
| chalk | 5.6.1 | 299.99 |
| ansi-styles | 6.2.2 | 371.41 |
| strip-ansi | 7.1.1 | - |
| supports-color | 10.2.1 | - |
| is-arrayish | 0.3.3 | 73.8 |
| error-ex | 1.3.3 | - |
| simple-swizzle | 0.2.3 | 26.26 |

#### DuckDB Compromise (Sept 9, 2025)
| Package | Malicious Version | Weekly Downloads |
|---------|-------------------|------------------|
| duckdb | 1.3.3 | 148,000 |
| @duckdb/node-api | 1.3.3 | 87,000 |
| @duckdb/node-bindings | 1.3.3 | 87,000 |
| @duckdb/duckdb-wasm | 1.29.2 | 64,000 |

#### Additional Packages
| Package | Malicious Version | Status |
|---------|-------------------|--------|
| @coveops/abi | 2.0.1 | Quickly removed |
| proto-tinker-wc | 0.1.87 | Low impact |
| prebid | 10.9.1, 10.9.2 | Multiple versions |

Full details in `malicious_packages.json`

### Malware Behavior
- Executes in browser context
- Hooks wallet transaction APIs
- Swaps recipient addresses before signing
- Uses visually similar addresses (Levenshtein algorithm)
- No C2 communication (uses hardcoded addresses)

## Troubleshooting

### Common Issues

**Issue**: "Cannot access repository"
```powershell
# Solution: Check API key and URL format
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://artifactory.company.com/artifactory/api/npm/npm-repo/" -ApiKey "YOUR_KEY"
```

**Issue**: "Script execution policy error"
```powershell
# Solution: Temporarily bypass execution policy
powershell -ExecutionPolicy Bypass -File .\Scan-NPMRepository.ps1 -LocalPath "."
```

**Issue**: "Rate limit exceeded"
```powershell
# Solution: Add delay between requests or use API key
.\Scan-NPMRepository.ps1 -RepositoryUrl "URL" -ApiKey "KEY"
```

## Support & Contributions

### Reporting Issues
If you find false positives or false negatives, please report them with:
- Package name and version
- Scanner output
- package.json contents

### Updates
Check for updates to `malicious_packages.json` as new threats emerge.

## References

- [Aikido Security Blog](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
- [Malware Analysis](https://jdstaerk.substack.com/p/we-just-found-malicious-code-in-the)
- [HackerNews Discussion](https://news.ycombinator.com/item?id=45169794)
- [AlienVault OTX Pulse](https://otx.alienvault.com/pulse/68c16a7d9c09dc1274872fab)

## License

This tool is provided as-is for security scanning purposes. Use responsibly and in accordance with your organization's security policies.

---

<div align="center">
  <h3>🛡️ Crimson7 Security Toolkit</h3>
  <p><strong>Advanced Supply Chain Security Analysis</strong></p>
  <p><a href="https://crimson7.io" target="_blank">https://crimson7.io</a></p>
  
  **Last Updated**: September 10, 2025  
  **Version**: 1.1.0 (Final Draft)  
  **Status**: Production Draft - API-Based Scanning Only  
  **Package Database**: 25 malicious packages tracked
</div>
