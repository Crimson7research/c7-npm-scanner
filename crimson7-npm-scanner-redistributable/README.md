# Crimson7 NPM Security Scanner v1.2.0
## Shai Hulud Worm Update - Redistributable Package

**Detection Coverage**: 212 malicious packages across 3 major supply chain attacks
**Critical Update**: Includes detection for S1ngularity/Shai Hulud self-propagating worm (187 packages)

---

## 🚨 Quick Start

### 1. Scan Local Project
```powershell
.\Scan-NPMRepository.ps1 -LocalPath "C:\YourProject"
```

### 2. Deep Scan with Content Analysis
```powershell
.\Scan-NPMRepository.ps1 -LocalPath "C:\YourProject" -DeepScan
```

### 3. Scan NPM Registry Packages
```powershell
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://registry.npmjs.org/" -DeepScan
```

### 4. Scan JFrog Artifactory
```powershell
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://artifactory.company.com/artifactory/api/npm/npm-repo/" -ApiKey "YOUR_KEY"
```

---

## 📁 Package Contents

| File | Description |
|------|-------------|
| `Scan-NPMRepository.ps1` | Main scanner script |
| `malicious_packages.json` | Database of 212 compromised packages |
| `Generate-HTMLReport.ps1` | HTML report generator |
| `QUICK_START.md` | Basic usage guide |
| `CHANGELOG.md` | Version history |

---

## 🎯 What It Detects

### Known Malicious Packages (212 total)
- **September 8, 2025**: Initial compromise (18 packages) - debug, chalk, ansi-styles, etc.
- **September 9, 2025**: DuckDB packages (4 packages)
- **September 16, 2025**: Shai Hulud Worm (187 packages) - Self-propagating attack

### Advanced Threat Patterns
- **Obfuscation**: Hex-variable patterns, encoded strings
- **Cryptocurrency Theft**: Wallet hijacking code
- **Worm Propagation**: GitHub Actions manipulation, token theft
- **Supply Chain**: Version substitution attacks

---

## 🔧 Command Options

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-LocalPath` | Scan local project directory | `-LocalPath "C:\Projects\MyApp"` |
| `-RepositoryUrl` | Remote repository URL | `-RepositoryUrl "https://registry.npmjs.org/"` |
| `-ApiKey` | Authentication for private repos | `-ApiKey "AKCp5..."` |
| `-DeepScan` | Download and analyze package contents | `-DeepScan` |
| `-All` | Extended package scanning | `-All` |
| `-OutputPath` | Custom output directory | `-OutputPath "C:\Reports"` |
| `-Verbose` | Detailed logging | `-Verbose` |

---

## 🚨 Critical Security Incidents

### S1ngularity/Shai Hulud Worm (Sept 16, 2025)
**187 packages compromised with self-propagation capability**

**Indicators:**
- Automated npm package publishing
- GitHub Actions workflow modifications
- Token exfiltration (npm, GitHub, environment variables)
- C2 communication to 185.174.137.80

**Affected Package Examples:**
- `@crowdstrike/*` packages (9 packages)
- `@ctrl/*` packages (16 packages)
- `@nativescript-community/*` packages (20+ packages)
- `@operato/*` packages (13 packages)

### Immediate Actions if Detected:
1. **ISOLATE** affected systems immediately
2. **REVOKE** all npm and GitHub tokens
3. **AUDIT** published packages for unauthorized versions
4. **CHECK** GitHub Actions workflows for modifications
5. **RESET** all development environment credentials

---

## 📊 Output Interpretation

| Status | Meaning | Action |
|--------|---------|--------|
| **MALICIOUS** | Known compromised package | Immediate removal required |
| **SUSPICIOUS** | Obfuscation patterns detected | Manual review needed |
| **CHECK_REQUIRED** | Parsing errors | Investigation required |
| **CLEAN** | No threats detected | Safe to use |

### Exit Codes
- `0` - No threats detected
- `1` - Suspicious packages found
- `2` - Malicious packages confirmed

---

## 🛠 System Requirements

- **PowerShell**: 5.1+ (Windows) or 7+ (cross-platform)
- **Network**: Internet access for registry scanning
- **Permissions**: File system read access for local scanning

---

## 🔍 Example Scan Output

```
🔍 Crimson7 NPM Security Scanner v1.2.0
📊 Scanning 25 packages...

❌ MALICIOUS: debug@4.4.2
   └─ Known S1ngularity compromise (Sept 8, 2025)
   └─ SHA1: c26e923750ff24150d13dea46e0c9d848b390f0f

⚠️  CRITICAL: @crowdstrike/commitlint@8.1.1
   └─ Shai Hulud worm detected (Sept 16, 2025)
   └─ GitHub Actions manipulation patterns

✅ CLEAN: lodash@4.17.21

📈 Summary: 2 threats detected, 23 clean packages
```

---

## 🆘 Support & Updates

- **Threat Intelligence**: Updates available at GitHub repository
- **Issue Reporting**: Submit findings for false positive/negative analysis
- **Security Updates**: Monitor for new threat intelligence releases

---

## ⚖️ License & Usage

This tool is provided for security scanning purposes. Use in accordance with your organization's security policies and applicable laws.

---

**🛡️ Crimson7 Security Research**
**Last Updated**: September 19, 2025
**Version**: 1.2.0 (Shai Hulud Update)