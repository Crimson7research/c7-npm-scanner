# Crimson7 NPM Security Scanner - Changelog

## Version 1.1.0 (September 10, 2025)

### 🚨 Critical Updates
- **Expanded Threat Database**: Added 7 new malicious packages from ongoing compromise
- **Total Coverage**: Now detects 25 compromised packages (up from 18)

### 🆕 New Features
- **`-All` Parameter**: Comprehensive repository scanning (scans every package, not just known malicious ones)
- **Enhanced Deep Scan**: Improved package download and content analysis
- **Progress Tracking**: Better user feedback during long-running scans
- **Resource Warnings**: Alerts for resource-intensive operations

### 📦 New Malicious Packages Detected
#### DuckDB Compromise (September 9, 2025)
- `duckdb@1.3.3` (148,000 weekly downloads)
- `@duckdb/node-api@1.3.3` (87,000 weekly downloads)
- `@duckdb/node-bindings@1.3.3` (87,000 weekly downloads) 
- `@duckdb/duckdb-wasm@1.29.2` (64,000 weekly downloads)

#### Additional Discoveries
- `@coveops/abi@2.0.1` (quickly removed after discovery)
- `proto-tinker-wc@0.1.87` (75 downloads of compromised version)
- `prebid@10.9.1` and `prebid@10.9.2` (196 total downloads)

### 🛠️ Improvements
- **Cleaner UI**: Removed ASCII art banner that rendered poorly on Windows
- **Better Error Handling**: Improved timeout and API error management
- **Enhanced Documentation**: Updated README with new command options
- **Execution Policy**: Added comprehensive PowerShell execution policy bypass instructions

### 🔧 Technical Changes
- Enhanced `Get-PackageTarball` function for better package extraction
- Improved obfuscation pattern detection (`const _0x112` signature)
- Better handling of scoped packages (packages starting with `@`)
- Enhanced progress reporting for large repository scans

### ⚠️ Important Notes
- **Resource Usage**: The `-All` parameter is very resource-intensive and should be used carefully
- **Rate Limits**: Consider using API keys to avoid rate limiting on large scans
- **Windows Compatibility**: Removed problematic ASCII art that caused rendering issues

### 📊 Statistics
- **Malicious Packages**: 25 total (7 new this version)
- **Detection Signatures**: 8 obfuscation patterns
- **Known Hashes**: 5 confirmed malicious file hashes
- **Cryptocurrency Networks**: Supports detection of 10 different wallet types

---

## Version 1.0.0 (September 10, 2025)

### 🚀 Initial Release
- Detection of 18 compromised NPM packages from September 2025 supply chain attack
- Local directory scanning capability
- Remote repository scanning (JFrog Artifactory, NPM Registry)
- Deep scan functionality for obfuscation pattern detection
- HTML report generation with Crimson7 branding
- Cross-platform PowerShell support (Windows PowerShell 5.1+ and PowerShell Core 7+)

### Core Features
- **Exact Version Matching**: Detects known malicious package versions
- **Pattern Detection**: Identifies obfuscated malware signatures
- **Multi-format Output**: JSON reports, CSV exports, and HTML dashboards
- **API Integration**: Support for authenticated repository access
- **Cryptocurrency Wallet Protection**: Detects wallet hijacking malware

### Supported Repositories
- NPM Registry (registry.npmjs.org)
- JFrog Artifactory instances
- Local file system scanning
- Any npm-compatible package repository

---

*For technical support and updates, visit [https://crimson7.io](https://crimson7.io)*