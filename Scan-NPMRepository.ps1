<#
.SYNOPSIS
    Crimson7 NPM Security Scanner - Advanced supply chain security analysis for NPM repositories
    
.DESCRIPTION
    Crimson7 NPM Security Scanner provides advanced supply chain security analysis.
    Scans remote NPM repositories (JFrog Artifactory, npm registry) or local directories
    for malicious NPM packages and obfuscation patterns from the September 2025 compromise.
    
    Part of the Crimson7 security toolkit - visit https://crimson7.io for more tools.
    
.PARAMETER RepositoryUrl
    The base URL of the NPM repository (e.g., https://artifactory.company.com/artifactory/npm-repo/)
    
.PARAMETER LocalPath
    Local directory path to scan for package.json files
    
.PARAMETER ApiKey
    API key for authenticated repository access (optional)
    
.PARAMETER OutputPath
    Path for output report (default: current directory)
    
.PARAMETER DeepScan
    Enable deep scanning of .tgz archives for obfuscation patterns
    
.PARAMETER All
    When combined with DeepScan, scan ALL packages in the repository (very resource intensive)
    
.EXAMPLE
    .\Scan-NPMRepository.ps1 -RepositoryUrl "https://artifactory.company.com/artifactory/npm-repo/" -ApiKey "AKCp5..."
    
.EXAMPLE
    .\Scan-NPMRepository.ps1 -LocalPath "C:\Projects\MyApp" -DeepScan
    
.EXAMPLE
    .\Scan-NPMRepository.ps1 -RepositoryUrl "https://registry.npmjs.org" -DeepScan -All
    WARNING: This will scan ALL packages in the repository - very resource intensive!

    
.NOTES
    Crimson7 NPM Security Scanner
    Advanced Supply Chain Security Analysis
    https://crimson7.io
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$RepositoryUrl,
    
    [Parameter(Mandatory=$false)]
    [string]$LocalPath,
    
    [Parameter(Mandatory=$false)]
    [string]$ApiKey,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory=$false)]
    [switch]$DeepScan,
    
    [Parameter(Mandatory=$false)]
    [switch]$All
)

# Display Crimson7 banner
Write-Host "`n===== CRIMSON7 NPM SECURITY SCANNER v1.1 =====" -ForegroundColor Red
Write-Host "Advanced Supply Chain Security Analysis" -ForegroundColor Gray  
Write-Host "https://crimson7.io" -ForegroundColor Cyan
Write-Host "===============================================`n" -ForegroundColor Red

# Ensure at least one source is specified
if (-not $RepositoryUrl -and -not $LocalPath) {
    Write-Error "Please specify either -RepositoryUrl or -LocalPath"
    exit 1
}

# Validate and fix JFrog URL if needed
if ($RepositoryUrl) {
    # Check if user provided a UI URL and convert it
    if ($RepositoryUrl -match "/ui/native/") {
        Write-ColorOutput "Detected JFrog UI URL. Converting to API URL..." -Level "Info"
        $originalUrl = $RepositoryUrl
        
        # Extract server and repo name from UI URL
        if ($RepositoryUrl -match "^(https?://[^/]+)/ui/native/([^/]+)") {
            $server = $Matches[1]
            $repoName = $Matches[2]
            $RepositoryUrl = "$server/artifactory/api/npm/$repoName/"
            Write-ColorOutput "Converted URL: $RepositoryUrl" -Level "Info"
        }
    }
    
    # Ensure URL ends with slash
    if (-not $RepositoryUrl.EndsWith("/")) {
        $RepositoryUrl += "/"
    }
    
    # Note: URL validation moved after function definitions
}

# Load malicious package definitions
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$maliciousPackagesJson = Get-Content -Path "$scriptDir\malicious_packages.json" -Raw | ConvertFrom-Json

# Color coding for output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    switch ($Level) {
        "Critical" { Write-Host $Message -ForegroundColor Red }
        "Suspicious" { Write-Host $Message -ForegroundColor Yellow }
        "Check" { Write-Host $Message -ForegroundColor Cyan }
        "Clean" { Write-Host $Message -ForegroundColor Green }
        "Info" { Write-Host $Message -ForegroundColor White }
    }
}

# URL validation (now that Write-ColorOutput is defined)
if ($RepositoryUrl -and $RepositoryUrl -match "/artifactory/[^/]+/$" -and $RepositoryUrl -notmatch "/api/") {
    Write-ColorOutput "TIP: Consider using API endpoint for better results:" -Level "Info"
    $suggestedUrl = $RepositoryUrl -replace "/artifactory/([^/]+)/$", "/artifactory/api/npm/`$1/"
    Write-ColorOutput "  $suggestedUrl" -Level "Info"
}

# Warning for -All parameter usage (must be after Write-ColorOutput function is defined)
if ($All -and -not $DeepScan) {
    Write-ColorOutput "[WARNING] -All parameter requires -DeepScan to be enabled. Ignoring -All." -Level "Check"
    $All = $false
}

if ($All -and $DeepScan) {
    Write-ColorOutput "[WARNING] Using -All with -DeepScan will scan ALL packages in the repository!" -Level "Check"
    Write-ColorOutput "[WARNING] This is very resource intensive and may take a long time." -Level "Check"
    Write-ColorOutput "[WARNING] Press Ctrl+C within 10 seconds to cancel, or wait to continue..." -Level "Check"
    Start-Sleep -Seconds 10
}

# Initialize results
$results = @{
    ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Repository = if ($RepositoryUrl) { $RepositoryUrl } else { $LocalPath }
    TotalPackagesScanned = 0
    MaliciousPackagesFound = @()
    SuspiciousPackagesFound = @()
    RequireManualCheck = @()
    CleanPackages = @()
}

# Function to check if package version is malicious
function Test-MaliciousPackage {
    param(
        [string]$PackageName,
        [string]$Version
    )
    
    $maliciousPackage = $maliciousPackagesJson.malicious_packages | Where-Object { $_.name -eq $PackageName }
    
    if ($maliciousPackage -and $maliciousPackage.malicious_version -eq $Version) {
        return @{
            Status = "MALICIOUS"
            Details = "Exact match for compromised version $($maliciousPackage.malicious_version)"
            Severity = $maliciousPackage.severity
        }
    }
    
    return $null
}

# Function to scan JavaScript content for obfuscation patterns
function Test-ObfuscationPatterns {
    param(
        [string]$Content
    )
    
    $suspiciousPatterns = @()
    
    # Check for specific obfuscation pattern
    if ($Content -match "const\s+_0x112") {
        $suspiciousPatterns += "Found obfuscation pattern: const _0x112"
    }
    
    # Check for general obfuscation
    if ($Content -match "_0x[0-9a-f]{4,}") {
        $matches = [regex]::Matches($Content, "_0x[0-9a-f]{4,}")
        if ($matches.Count -gt 10) {
            $suspiciousPatterns += "Heavy obfuscation detected: $($matches.Count) hex-encoded variables"
        }
    }
    
    # Check for wallet-related functions
    if ($Content -match "checkethereumw|stealthProxyControl") {
        $suspiciousPatterns += "Found malware function signatures"
    }
    
    # Check for Levenshtein algorithm
    if ($Content -match "levenshtein|distance.*similarity") {
        $suspiciousPatterns += "Found Levenshtein distance algorithm (address swapping)"
    }
    
    # Check for multiple wallet addresses
    $btcAddresses = [regex]::Matches($Content, "\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
    $ethAddresses = [regex]::Matches($Content, "\b0x[a-fA-F0-9]{40}\b")
    
    if ($btcAddresses.Count -gt 5) {
        $suspiciousPatterns += "Multiple Bitcoin addresses found: $($btcAddresses.Count)"
    }
    
    if ($ethAddresses.Count -gt 5) {
        $suspiciousPatterns += "Multiple Ethereum addresses found: $($ethAddresses.Count)"
    }
    
    return $suspiciousPatterns
}

# Function to scan package.json file
function Test-PackageJson {
    param(
        [string]$PackageJsonPath
    )
    
    try {
        $packageJson = Get-Content -Path $PackageJsonPath -Raw | ConvertFrom-Json
        $packageName = $packageJson.name
        $packageVersion = $packageJson.version
        
        Write-ColorOutput "Scanning package: $packageName@$packageVersion" -Level "Info"
        
        $result = @{
            Name = $packageName
            Version = $packageVersion
            Path = $PackageJsonPath
            Status = "CLEAN"
            Details = @()
        }
        
        # Check dependencies
        $allDeps = @{}
        if ($packageJson.dependencies) {
            $packageJson.dependencies.PSObject.Properties | ForEach-Object {
                $allDeps[$_.Name] = $_.Value
            }
        }
        if ($packageJson.devDependencies) {
            $packageJson.devDependencies.PSObject.Properties | ForEach-Object {
                $allDeps[$_.Name] = $_.Value
            }
        }
        
        # Check each dependency
        foreach ($dep in $allDeps.GetEnumerator()) {
            $depName = $dep.Key
            $depVersion = $dep.Value -replace '[\^~>=<]', ''
            
            $maliciousCheck = Test-MaliciousPackage -PackageName $depName -Version $depVersion
            
            if ($maliciousCheck) {
                $result.Status = "MALICIOUS"
                $result.Details += "Malicious dependency: $depName@$depVersion - $($maliciousCheck.Details)"
                Write-ColorOutput "  [CRITICAL] Found malicious package: $depName@$depVersion" -Level "Critical"
            }
        }
        
        # Deep scan if enabled
        if ($DeepScan -and $result.Status -ne "MALICIOUS") {
            $packageDir = Split-Path -Parent $PackageJsonPath
            $jsFiles = Get-ChildItem -Path $packageDir -Filter "*.js" -Recurse -ErrorAction SilentlyContinue | 
                       Where-Object { $_.FullName -notmatch "node_modules|test|spec" }
            
            foreach ($jsFile in $jsFiles) {
                $content = Get-Content -Path $jsFile.FullName -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    $patterns = Test-ObfuscationPatterns -Content $content
                    if ($patterns.Count -gt 0) {
                        $result.Status = "SUSPICIOUS"
                        $result.Details += "File: $($jsFile.Name) - $($patterns -join '; ')"
                        Write-ColorOutput "  [SUSPICIOUS] $($jsFile.Name): $($patterns[0])" -Level "Suspicious"
                    }
                }
            }
        }
        
        return $result
    }
    catch {
        Write-ColorOutput "  [ERROR] Failed to parse package.json: $_" -Level "Critical"
        return @{
            Name = "Unknown"
            Version = "Unknown"
            Path = $PackageJsonPath
            Status = "ERROR"
            Details = @("Failed to parse: $_")
        }
    }
}

# Function to download and extract npm package tarball for deep scanning
function Get-PackageTarball {
    param(
        [string]$PackageName,
        [string]$Version,
        [string]$RepoUrl,
        [hashtable]$Headers
    )
    
    try {
        # Construct tarball URL based on repository type
        if ($RepoUrl -like "*registry.npmjs.org*") {
            # NPM Registry format - need to get the actual tarball URL from package metadata
            $metadataUrl = "$RepoUrl$PackageName/$Version"
            $metadata = Invoke-RestMethod -Uri $metadataUrl -Headers $Headers -ErrorAction Stop
            $tarballUrl = $metadata.dist.tarball
        } else {
            # JFrog Artifactory format  
            $tarballUrl = "$RepoUrl$PackageName/-/$PackageName-$Version.tgz"
        }
        
        Write-ColorOutput "      [INFO] Downloading $PackageName@$Version for deep scan..." -Level "Info"
        
        # Create temporary directory
        $tempDir = New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item -ItemType Directory -Path $_ }
        $tarballPath = Join-Path $tempDir "$PackageName-$Version.tgz"
        
        # Download tarball
        Invoke-WebRequest -Uri $tarballUrl -OutFile $tarballPath -Headers $Headers -ErrorAction Stop
        
        # Extract using tar (available on Windows 10+, macOS, Linux)
        if (Get-Command tar -ErrorAction SilentlyContinue) {
            & tar -xzf $tarballPath -C $tempDir 2>$null
        } else {
            # Fallback for older Windows systems without tar
            Write-ColorOutput "      [WARNING] tar command not available, skipping deep scan" -Level "Check"
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
            return $null
        }
        
        return $tempDir
    }
    catch {
        Write-ColorOutput "      [WARNING] Could not download package for deep scan: $_" -Level "Check"
        if ($tempDir -and (Test-Path $tempDir)) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        return $null
    }
}

# Function to scan remote repository
function Scan-RemoteRepository {
    param(
        [string]$RepoUrl,
        [string]$ApiKey
    )
    
    Write-ColorOutput "`nScanning remote repository: $RepoUrl" -Level "Info"
    if ($All -and $DeepScan) {
        Write-ColorOutput "[COMPREHENSIVE MODE] Scanning ALL packages with deep scan enabled" -Level "Check"
    }
    Write-ColorOutput "========================================" -Level "Info"
    
    # Set up headers
    $headers = @{}
    if ($ApiKey) {
        $headers["X-JFrog-Art-Api"] = $ApiKey
        # Alternative auth header for npm registry
        $headers["Authorization"] = "Bearer $ApiKey"
    }
    
    # Determine repository type and set appropriate API endpoint
    $isNpmRegistry = $RepoUrl -like "*registry.npmjs.org*"
    $isJFrog = $RepoUrl -like "*artifactory*"
    
    if ($isNpmRegistry) {
        Write-ColorOutput "[INFO] Detected NPM Registry - using targeted package scanning" -Level "Info"
        if ($All) {
            Write-ColorOutput "[WARNING] -All parameter with NPM Registry will scan many popular packages. This may be slow." -Level "Check"
            Write-ColorOutput "[INFO] Note: Full NPM registry scan not implemented. Scanning extended package list instead." -Level "Info"
        }
    }
    
    # Try to list packages (JFrog Artifactory API) - skip for npm registry
    if ($isNpmRegistry) {
        # Force exception to use alternative method for npm registry
        $useAlternativeMethod = $true
    } else {
        $useAlternativeMethod = $false
    }
    
    if (-not $useAlternativeMethod) {
        try {
        # Construct proper JFrog API URL
        if ($RepoUrl -match "/artifactory/api/npm/([^/]+)/?$") {
            # Already API format: https://server/artifactory/api/npm/repo-name/
            $repoName = $Matches[1]
            $apiUrl = "$RepoUrl/../storage/$repoName"
        } elseif ($RepoUrl -match "/artifactory/([^/]+)/?$") {
            # Direct format: https://server/artifactory/repo-name/
            $repoName = $Matches[1]
            $baseUrl = $RepoUrl -replace "/artifactory/[^/]+/?$", ""
            $apiUrl = "$baseUrl/artifactory/api/storage/$repoName"
        } else {
            throw "Unable to determine JFrog repository structure from URL: $RepoUrl"
        }
        
        Write-ColorOutput "[DEBUG] Using JFrog API endpoint: $apiUrl" -Level "Info"
        $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get -ErrorAction Stop
        
        # Count total packages for progress tracking
        $totalPackages = ($response.children | Where-Object { $_.folder }).Count
        $currentPackage = 0
        
        if ($All) {
            Write-ColorOutput "Found $totalPackages packages in repository. Starting comprehensive scan..." -Level "Info"
        }
        
        # Process each package
        foreach ($item in $response.children) {
            if ($item.folder) {
                $currentPackage++
                $packageName = $item.uri.TrimStart('/')
                
                # Progress indicator for comprehensive scanning
                if ($All) {
                    $percentComplete = [math]::Round(($currentPackage / $totalPackages) * 100, 1)
                    Write-Progress -Activity "Comprehensive Repository Scan" -Status "Scanning package $currentPackage of $totalPackages ($percentComplete%)" -PercentComplete $percentComplete -Id 1
                }
                
                # Check if this is a malicious package name
                $isMalicious = $maliciousPackagesJson.malicious_packages | Where-Object { $_.name -eq $packageName }
                
                # Process package if it's malicious OR if -All flag is used
                if ($isMalicious -or $All) {
                    if ($All -and -not $isMalicious) {
                        Write-ColorOutput "  [SCAN] Scanning all packages: $packageName" -Level "Info"
                    }
                    Write-ColorOutput "  [CHECK] Found package in repository: $packageName" -Level "Check"
                    
                    # Get package versions
                    $versionsUrl = "$apiUrl/$packageName"
                    try {
                        $versions = Invoke-RestMethod -Uri $versionsUrl -Headers $headers -Method Get -ErrorAction Stop
                        
                        foreach ($version in $versions.children) {
                            if ($version.folder) {
                                $versionNum = $version.uri.TrimStart('/')
                                $malCheck = Test-MaliciousPackage -PackageName $packageName -Version $versionNum
                                
                                if ($malCheck) {
                                    Write-ColorOutput "    [CRITICAL] Malicious version found: $packageName@$versionNum" -Level "Critical"
                                    $results.MaliciousPackagesFound += @{
                                        Package = "$packageName@$versionNum"
                                        Details = $malCheck.Details
                                    }
                                }
                                else {
                                    Write-ColorOutput "    [CLEAN] Safe version: $packageName@$versionNum" -Level "Clean"
                                }
                                
                                # Deep scan if enabled and not already marked as malicious
                                if ($DeepScan -and -not $malCheck) {
                                    try {
                                        $tempDir = Get-PackageTarball -PackageName $packageName -Version $versionNum -RepoUrl $RepoUrl -Headers $headers
                                        
                                        if ($tempDir) {
                                            # Find JavaScript files (usually in package/ subdirectory after extraction)
                                            $packageDir = Join-Path $tempDir "package"
                                            
                                            if (Test-Path $packageDir) {
                                                # Check main entry point files
                                                $mainFiles = @("index.js", "main.js", "lib/index.js")
                                                $foundObfuscation = $false
                                                
                                                foreach ($mainFile in $mainFiles) {
                                                    $jsPath = Join-Path $packageDir $mainFile
                                                    if (Test-Path $jsPath) {
                                                        $content = Get-Content -Path $jsPath -Raw -ErrorAction SilentlyContinue
                                                        
                                                        # Simple check for the specific obfuscation pattern
                                                        if ($content -and $content -match "const\s+_0x112") {
                                                            Write-ColorOutput "      [SUSPICIOUS] Obfuscation pattern found in $mainFile" -Level "Suspicious"
                                                            $results.SuspiciousPackagesFound += @{
                                                                Name = $packageName
                                                                Version = $versionNum
                                                                Details = @("Obfuscation pattern 'const _0x112' found in $mainFile")
                                                                Path = $RepoUrl
                                                                Status = "SUSPICIOUS"
                                                            }
                                                            $foundObfuscation = $true
                                                            break
                                                        }
                                                    }
                                                }
                                                
                                                if (-not $foundObfuscation) {
                                                    Write-ColorOutput "      [CLEAN] No obfuscation patterns found in main files" -Level "Clean"
                                                }
                                            }
                                            
                                            # Clean up temp directory
                                            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                                        }
                                    }
                                    catch {
                                        Write-ColorOutput "      [WARNING] Could not deep scan $packageName@$versionNum : $_" -Level "Check"
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-ColorOutput "    [ERROR] Could not retrieve versions for $packageName" -Level "Critical"
                    }
                } # End of isMalicious or All check
            }
            
            $results.TotalPackagesScanned++
        }
        
        # Clear progress bar when done
        if ($All) {
            Write-Progress -Activity "Comprehensive Repository Scan" -Completed -Id 1
            Write-ColorOutput "Comprehensive scan completed. Scanned $currentPackage packages." -Level "Info"
        }
        }
        catch {
            Write-ColorOutput "[ERROR] JFrog repository access failed: $_" -Level "Critical"
        }
    }
    
    # Alternative method (always used for npm registry, fallback for JFrog)
    if ($useAlternativeMethod -or $?) {
        Write-ColorOutput "[INFO] Using targeted scanning method for known malicious packages..." -Level "Info"
        
        # Determine which packages to scan
        $packagesToScan = $maliciousPackagesJson.malicious_packages
        
        # If -All is enabled and we're on NPM registry, add popular packages
        if ($All -and $isNpmRegistry) {
            Write-ColorOutput "[INFO] -All mode: Adding popular packages to scan list..." -Level "Info"
            
            # Add popular packages that might be targeted in future attacks
            $popularPackages = @(
                @{name="lodash"; malicious_version=""}
                @{name="react"; malicious_version=""}
                @{name="express"; malicious_version=""}
                @{name="axios"; malicious_version=""}
                @{name="moment"; malicious_version=""}
                @{name="underscore"; malicious_version=""}
                @{name="request"; malicious_version=""}
                @{name="commander"; malicious_version=""}
                @{name="colors"; malicious_version=""}
                @{name="mkdirp"; malicious_version=""}
                @{name="glob"; malicious_version=""}
                @{name="rimraf"; malicious_version=""}
                @{name="bluebird"; malicious_version=""}
                @{name="yargs"; malicious_version=""}
                @{name="inquirer"; malicious_version=""}
                @{name="fs-extra"; malicious_version=""}
                @{name="webpack"; malicious_version=""}
                @{name="babel-core"; malicious_version=""}
                @{name="typescript"; malicious_version=""}
                @{name="eslint"; malicious_version=""}
            )
            
            # Combine malicious packages with popular packages for comprehensive scan
            $packagesToScan = $maliciousPackagesJson.malicious_packages + $popularPackages
            Write-ColorOutput "[INFO] Extended scan will check $($packagesToScan.Count) packages total" -Level "Info"
        }
        
        # Enhanced direct package access for selected packages
        foreach ($package in $packagesToScan) {
            Write-ColorOutput "  [CHECK] Scanning for $($package.name)..." -Level "Check"
            
            # For npm registry, use the package metadata API
            if ($isNpmRegistry) {
                $packageUrl = "$RepoUrl$($package.name)"
            } else {
                $packageUrl = "$RepoUrl/$($package.name)/package.json"
            }
            
            try {
                $packageJson = Invoke-RestMethod -Uri $packageUrl -Headers $headers -Method Get -ErrorAction Stop
                
                # Handle npm registry response format
                if ($isNpmRegistry -and $packageJson.'dist-tags') {
                    $latestVersion = $packageJson.'dist-tags'.latest
                    $allVersions = $packageJson.versions.PSObject.Properties.Name
                    
                    # Check if malicious version exists (only for packages that have malicious versions)
                    if ($package.malicious_version -and $package.malicious_version -in $allVersions) {
                        Write-ColorOutput "    [CRITICAL] Malicious version $($package.malicious_version) found in repository!" -Level "Critical"
                        
                        $results.MaliciousPackagesFound += @{
                            Package = "$($package.name)@$($package.malicious_version)"
                            Details = "Malicious version available in repository (latest: $latestVersion)"
                        }
                        
                        # Deep scan if enabled
                        if ($DeepScan) {
                            try {
                                $tempDir = Get-PackageTarball -PackageName $package.name -Version $package.malicious_version -RepoUrl $RepoUrl -Headers $headers
                                
                                if ($tempDir) {
                                    Write-ColorOutput "      [INFO] Deep scanning $($package.name)@$($package.malicious_version)..." -Level "Info"
                                    
                                    # Find the package directory (usually 'package' after extraction)
                                    $packageDir = Join-Path $tempDir "package"
                                    
                                    if (Test-Path $packageDir) {
                                        # Look for main entry point files
                                        $mainFiles = @("index.js", "main.js", "lib/index.js")
                                        
                                        foreach ($mainFile in $mainFiles) {
                                            $jsPath = Join-Path $packageDir $mainFile
                                            if (Test-Path $jsPath) {
                                                $content = Get-Content -Path $jsPath -Raw -ErrorAction SilentlyContinue
                                                
                                                if ($content -and $content -match "const\s+_0x112") {
                                                    Write-ColorOutput "      [CONFIRMED] Obfuscation pattern 'const _0x112' found in $mainFile" -Level "Critical"
                                                    break
                                                }
                                            }
                                        }
                                    }
                                    
                                    # Clean up
                                    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                                }
                            }
                            catch {
                                Write-ColorOutput "      [WARNING] Could not deep scan: $_" -Level "Check"
                            }
                        }
                    }
                    elseif ($package.malicious_version) {
                        Write-ColorOutput "    [CLEAN] Malicious version $($package.malicious_version) not found (latest: $latestVersion)" -Level "Clean"
                    }
                    else {
                        # This is a popular package added for -All scanning (no known malicious version)
                        Write-ColorOutput "    [INFO] Scanning popular package $($package.name) (latest: $latestVersion)" -Level "Info"
                        
                        # Deep scan the latest version if enabled
                        if ($DeepScan) {
                            try {
                                $tempDir = Get-PackageTarball -PackageName $package.name -Version $latestVersion -RepoUrl $RepoUrl -Headers $headers
                                
                                if ($tempDir) {
                                    Write-ColorOutput "      [INFO] Deep scanning $($package.name)@$latestVersion..." -Level "Info"
                                    
                                    # Find the package directory
                                    $packageDir = Join-Path $tempDir "package"
                                    
                                    if (Test-Path $packageDir) {
                                        # Look for main entry point files
                                        $mainFiles = @("index.js", "main.js", "lib/index.js", "src/index.js")
                                        $foundSuspicious = $false
                                        
                                        foreach ($mainFile in $mainFiles) {
                                            $jsPath = Join-Path $packageDir $mainFile
                                            if (Test-Path $jsPath) {
                                                $content = Get-Content -Path $jsPath -Raw -ErrorAction SilentlyContinue
                                                
                                                if ($content) {
                                                    # Check for obfuscation patterns
                                                    if ($content -match "const\s+_0x112") {
                                                        Write-ColorOutput "      [SUSPICIOUS] Obfuscation pattern 'const _0x112' found in $mainFile" -Level "Suspicious"
                                                        $results.SuspiciousPackagesFound += @{
                                                            Name = $package.name
                                                            Version = $latestVersion
                                                            Details = @("Obfuscation pattern 'const _0x112' found in $mainFile")
                                                            Path = $RepoUrl
                                                            Status = "SUSPICIOUS"
                                                        }
                                                        $foundSuspicious = $true
                                                        break
                                                    }
                                                    # Check for other suspicious patterns
                                                    elseif ($content -match "_0x[0-9a-f]{4,}.*_0x[0-9a-f]{4,}.*_0x[0-9a-f]{4,}") {
                                                        Write-ColorOutput "      [SUSPICIOUS] Heavy obfuscation patterns detected in $mainFile" -Level "Suspicious"
                                                        $results.SuspiciousPackagesFound += @{
                                                            Name = $package.name
                                                            Version = $latestVersion
                                                            Details = @("Heavy obfuscation patterns detected in $mainFile")
                                                            Path = $RepoUrl
                                                            Status = "SUSPICIOUS"
                                                        }
                                                        $foundSuspicious = $true
                                                        break
                                                    }
                                                }
                                            }
                                        }
                                        
                                        if (-not $foundSuspicious) {
                                            Write-ColorOutput "      [CLEAN] No suspicious patterns found in $($package.name)" -Level "Clean"
                                        }
                                    }
                                    
                                    # Clean up
                                    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                                }
                            }
                            catch {
                                Write-ColorOutput "      [WARNING] Could not deep scan $($package.name): $_" -Level "Check"
                            }
                        }
                    }
                }
                else {
                    # Handle direct package.json response (JFrog format)
                    if ($packageJson.version -eq $package.malicious_version) {
                        Write-ColorOutput "    [CRITICAL] Found malicious package: $($package.name)@$($package.malicious_version)" -Level "Critical"
                        $results.MaliciousPackagesFound += @{
                            Package = "$($package.name)@$($package.malicious_version)"
                            Details = "Exact malicious version match"
                        }
                    }
                    else {
                        Write-ColorOutput "    [CLEAN] Safe version found: $($package.name)@$($packageJson.version)" -Level "Clean"
                    }
                }
                
                $results.TotalPackagesScanned++
            }
            catch {
                Write-ColorOutput "    [INFO] Package $($package.name) not found in repository" -Level "Info"
            }
        }
    }
}

# Function to scan local directory
function Scan-LocalDirectory {
    param(
        [string]$Path
    )
    
    Write-ColorOutput "`nScanning local directory: $Path" -Level "Info"
    Write-ColorOutput "========================================" -Level "Info"
    
    # Find all package.json files
    $packageFiles = Get-ChildItem -Path $Path -Filter "package.json" -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -notmatch "node_modules" }
    
    Write-ColorOutput "Found $($packageFiles.Count) package.json files to scan" -Level "Info"
    
    foreach ($packageFile in $packageFiles) {
        $result = Test-PackageJson -PackageJsonPath $packageFile.FullName
        
        switch ($result.Status) {
            "MALICIOUS" { 
                $results.MaliciousPackagesFound += $result
                Write-ColorOutput "  [CRITICAL] Malicious package detected!" -Level "Critical"
            }
            "SUSPICIOUS" { 
                $results.SuspiciousPackagesFound += $result
                Write-ColorOutput "  [SUSPICIOUS] Suspicious patterns found" -Level "Suspicious"
            }
            "ERROR" { 
                $results.RequireManualCheck += $result
                Write-ColorOutput "  [CHECK] Manual review required" -Level "Check"
            }
            "CLEAN" { 
                $results.CleanPackages += $result
            }
        }
        
        $results.TotalPackagesScanned++
    }
}

# Main execution
Write-ColorOutput "`n===================================================" -Level "Info"
Write-ColorOutput "NPM Supply Chain Compromise Scanner v1.1" -Level "Info"
Write-ColorOutput "Scanning for September 2025 compromised packages" -Level "Info"
Write-ColorOutput "===================================================" -Level "Info"

# Perform scan based on input
if ($RepositoryUrl) {
    Scan-RemoteRepository -RepoUrl $RepositoryUrl -ApiKey $ApiKey
}

if ($LocalPath) {
    Scan-LocalDirectory -Path $LocalPath
}

# Generate summary
Write-ColorOutput "`n===================================================" -Level "Info"
Write-ColorOutput "CRIMSON7 SCAN SUMMARY" -Level "Info"
Write-ColorOutput "===================================================" -Level "Info"
Write-ColorOutput "Total packages scanned: $($results.TotalPackagesScanned)" -Level "Info"
Write-ColorOutput "Malicious packages found: $($results.MaliciousPackagesFound.Count)" -Level $(if ($results.MaliciousPackagesFound.Count -gt 0) { "Critical" } else { "Clean" })
Write-ColorOutput "Suspicious packages found: $($results.SuspiciousPackagesFound.Count)" -Level $(if ($results.SuspiciousPackagesFound.Count -gt 0) { "Suspicious" } else { "Clean" })
Write-ColorOutput "Packages requiring manual check: $($results.RequireManualCheck.Count)" -Level $(if ($results.RequireManualCheck.Count -gt 0) { "Check" } else { "Clean" })
Write-ColorOutput "Clean packages: $($results.CleanPackages.Count)" -Level "Clean"

# Export results
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportPath = Join-Path $OutputPath "npm_scan_report_$timestamp.json"
$results | ConvertTo-Json -Depth 10 | Set-Content -Path $reportPath

Write-ColorOutput "`n=== Crimson7 Security Analysis Complete ===" -Level "Info"
Write-ColorOutput "Detailed report saved to: $reportPath" -Level "Info"
Write-ColorOutput "Visit https://crimson7.io for more security tools" -Level "Info"

# Export CSV for critical findings
if ($results.MaliciousPackagesFound.Count -gt 0 -or $results.SuspiciousPackagesFound.Count -gt 0) {
    $csvPath = Join-Path $OutputPath "npm_scan_critical_$timestamp.csv"
    
    $csvData = @()
    
    foreach ($item in $results.MaliciousPackagesFound) {
        $csvData += [PSCustomObject]@{
            Status = "MALICIOUS"
            Package = $item.Package -replace '@', ' v'
            Details = ($item.Details -join '; ')
            Path = $item.Path
        }
    }
    
    foreach ($item in $results.SuspiciousPackagesFound) {
        $csvData += [PSCustomObject]@{
            Status = "SUSPICIOUS"
            Package = "$($item.Name) v$($item.Version)"
            Details = ($item.Details -join '; ')
            Path = $item.Path
        }
    }
    
    $csvData | Export-Csv -Path $csvPath -NoTypeInformation
    Write-ColorOutput "Critical findings exported to: $csvPath" -Level "Info"
}

# Return exit code based on findings
if ($results.MaliciousPackagesFound.Count -gt 0) {
    Write-ColorOutput "`n[CRITICAL] Malicious packages detected! Immediate action required!" -Level "Critical"
    exit 2
}
elseif ($results.SuspiciousPackagesFound.Count -gt 0) {
    Write-ColorOutput "`n[WARNING] Suspicious packages detected. Manual review recommended." -Level "Suspicious"
    exit 1
}
else {
    Write-ColorOutput "`n[SUCCESS] No malicious packages detected." -Level "Clean"
    exit 0
}