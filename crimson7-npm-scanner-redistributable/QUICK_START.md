# 🚀 Crimson7 NPM Scanner v1.1 - Quick Start Guide

## 30-Second Quick Start

```powershell
# 1. Scan your current project
.\Scan-NPMRepository.ps1 -LocalPath "."

# 2. Scan with deep analysis (recommended)
.\Scan-NPMRepository.ps1 -LocalPath "." -DeepScan

# 3. If execution policy blocks you:
powershell -ExecutionPolicy Bypass -File .\Scan-NPMRepository.ps1 -LocalPath "."
```

## What's New in v1.1

### 🆕 New `-All` Parameter
Scan **EVERY** package in a repository (not just known malicious ones):
```powershell
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://registry.npmjs.org/" -All
```
⚠️ **Warning**: This is resource-intensive! Use carefully.

### 📦 25 Malicious Packages Now Detected
- **Original 18**: debug, chalk, ansi-styles, etc.
- **New 7**: duckdb, @duckdb/node-api, @coveops/abi, prebid, etc.

## Common Use Cases

### 🏠 Local Project Scan
```powershell
# Basic scan
.\Scan-NPMRepository.ps1 -LocalPath "C:\Projects\MyApp"

# Deep scan for obfuscated code
.\Scan-NPMRepository.ps1 -LocalPath "." -DeepScan -Verbose
```

### 🌐 Remote Repository Scan
```powershell
# Public NPM registry
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://registry.npmjs.org/"

# Private JFrog Artifactory (with API key)
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://artifactory.company.com/artifactory/api/npm/npm-repo/" -ApiKey "YOUR_KEY"
```

### 🔍 Comprehensive Analysis
```powershell
# Scan everything with deep analysis (use carefully!)
.\Scan-NPMRepository.ps1 -RepositoryUrl "https://artifactory.company.com/artifactory/npm-repo/" -All -DeepScan -ApiKey "YOUR_KEY"
```

## Understanding Results

| Status | Color | Meaning | Action |
|--------|--------|---------|---------|
| **MALICIOUS** | 🔴 Red | Known compromised package | **Remove immediately** |
| **SUSPICIOUS** | 🟡 Yellow | Contains suspicious patterns | Manual review needed |
| **CHECK** | 🔵 Cyan | Needs investigation | Manual check required |
| **CLEAN** | 🟢 Green | No threats found | No action needed |

## Emergency Response

If you find **MALICIOUS** packages:

```bash
# 1. Stop all builds immediately
# 2. Remove contaminated dependencies
rm -rf node_modules package-lock.json

# 3. Clear cache
npm cache clean --force

# 4. Reinstall with exact versions
npm install --save-exact

# 5. Verify clean
.\Scan-NPMRepository.ps1 -LocalPath "." -DeepScan
```

## Common Issues

**"Execution Policy" Error:**
```powershell
powershell -ExecutionPolicy Bypass -File .\Scan-NPMRepository.ps1 -LocalPath "."
```

**"Repository Access" Error:**
- Check URL format (use API URL, not UI URL)
- Add `-ApiKey` for private repositories
- Verify network connectivity

**Rate Limiting:**
- Use `-ApiKey` parameter
- Reduce scan scope
- Add delays between requests

## Support

- 📖 Full documentation: `README.md`
- 🔄 Change log: `CHANGELOG.md`  
- 🌐 Website: [https://crimson7.io](https://crimson7.io)

---

**Version**: 1.1.0 | **Updated**: September 10, 2025 | **Packages Tracked**: 25