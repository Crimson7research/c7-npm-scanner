param(
    [Parameter(Mandatory=$true)]
    [string]$JsonReportPath,
    
    [string]$OutputPath = "npm_scan_report.html"
)

function Generate-HTMLReport {
    param([string]$JsonPath, [string]$HtmlPath)
    
    Write-Host "Generating HTML report from $JsonPath..."
    
    # Load the JSON report
    if (-not (Test-Path $JsonPath)) {
        Write-Error "JSON report file not found: $JsonPath"
        return
    }
    
    $scanData = Get-Content $JsonPath -Raw | ConvertFrom-Json
    
    # Calculate summary statistics
    $totalMalicious = $scanData.MaliciousPackagesFound.Count
    $totalSuspicious = $scanData.SuspiciousPackagesFound.Count
    $totalClean = $scanData.CleanPackages.Count
    $totalManualCheck = $scanData.RequireManualCheck.Count
    $totalScanned = $scanData.TotalPackagesScanned
    
    # Determine overall risk level
    $riskLevel = "LOW"
    $riskColor = "#28a745"
    if ($totalMalicious -gt 0) {
        $riskLevel = "CRITICAL"
        $riskColor = "#dc3545"
    } elseif ($totalSuspicious -gt 0) {
        $riskLevel = "HIGH"
        $riskColor = "#fd7e14"
    } elseif ($totalManualCheck -gt 0) {
        $riskLevel = "MEDIUM"
        $riskColor = "#ffc107"
    }
    
    # Generate HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Crimson7 NPM Package Security Scan Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #8b0000 0%, #dc143c 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #8b0000 0%, #b22222 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }
        
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.8;
        }
        
        .scan-info {
            background: #f8f9fa;
            padding: 20px 30px;
            border-bottom: 1px solid #e9ecef;
        }
        
        .scan-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        
        .scan-info-item {
            text-align: center;
        }
        
        .scan-info-value {
            font-size: 1.5em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .scan-info-label {
            font-size: 0.9em;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 5px;
        }
        
        .risk-assessment {
            padding: 30px;
            text-align: center;
            background: #f8f9fa;
        }
        
        .risk-badge {
            display: inline-block;
            padding: 15px 30px;
            border-radius: 50px;
            color: white;
            font-size: 1.3em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
        }
        
        .summary-card {
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transition: transform 0.2s;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
        }
        
        .card-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .card-label {
            font-size: 1.1em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .malicious { color: #dc3545; }
        .suspicious { color: #fd7e14; }
        .manual-check { color: #ffc107; }
        .clean { color: #28a745; }
        
        .findings {
            padding: 30px;
        }
        
        .findings h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        
        .finding-section {
            margin-bottom: 30px;
        }
        
        .finding-section h3 {
            color: #495057;
            margin-bottom: 15px;
            padding-bottom: 5px;
            border-bottom: 2px solid #e9ecef;
        }
        
        .package-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 5px solid;
        }
        
        .package-card.malicious {
            border-left-color: #dc3545;
            background: #f8d7da;
        }
        
        .package-card.suspicious {
            border-left-color: #fd7e14;
            background: #ffeaa7;
        }
        
        .package-card.manual-check {
            border-left-color: #ffc107;
            background: #fff3cd;
        }
        
        .package-name {
            font-size: 1.3em;
            font-weight: bold;
            margin-bottom: 10px;
            color: #2c3e50;
        }
        
        .package-version {
            color: #6c757d;
            font-size: 0.9em;
            margin-bottom: 10px;
        }
        
        .package-path {
            font-size: 0.8em;
            color: #6c757d;
            font-family: monospace;
            background: white;
            padding: 5px 10px;
            border-radius: 4px;
            margin-bottom: 10px;
        }
        
        .package-details {
            margin-top: 15px;
        }
        
        .detail-item {
            background: white;
            padding: 8px 12px;
            margin: 5px 0;
            border-radius: 4px;
            font-size: 0.9em;
            border-left: 3px solid #dc3545;
        }
        
        .no-findings {
            text-align: center;
            color: #6c757d;
            font-style: italic;
            padding: 20px;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }
        
        .timestamp {
            opacity: 0.7;
        }
        
        @media (max-width: 768px) {
            .summary-cards {
                grid-template-columns: 1fr;
            }
            
            .scan-info-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🛡️ Crimson7 NPM Security Scanner</h1>
            <div class="subtitle">Advanced Supply Chain Security Analysis | crimson7.io</div>
        </header>
        
        <div class="scan-info">
            <div class="scan-info-grid">
                <div class="scan-info-item">
                    <div class="scan-info-value">$($scanData.ScanDate)</div>
                    <div class="scan-info-label">Scan Date</div>
                </div>
                <div class="scan-info-item">
                    <div class="scan-info-value">$totalScanned</div>
                    <div class="scan-info-label">Packages Scanned</div>
                </div>
                <div class="scan-info-item">
                    <div class="scan-info-value">$($scanData.Repository -replace '.*[/\\]', '')</div>
                    <div class="scan-info-label">Repository</div>
                </div>
            </div>
        </div>
        
        <div class="risk-assessment">
            <div class="risk-badge" style="background-color: $riskColor;">
                Risk Level: $riskLevel
            </div>
            <div>Based on the analysis of $totalScanned package(s)</div>
        </div>
        
        <div class="summary-cards">
            <div class="summary-card">
                <div class="card-number malicious">$totalMalicious</div>
                <div class="card-label malicious">Malicious Packages</div>
            </div>
            <div class="summary-card">
                <div class="card-number suspicious">$totalSuspicious</div>
                <div class="card-label suspicious">Suspicious Packages</div>
            </div>
            <div class="summary-card">
                <div class="card-number manual-check">$totalManualCheck</div>
                <div class="card-label manual-check">Manual Check Required</div>
            </div>
            <div class="summary-card">
                <div class="card-number clean">$totalClean</div>
                <div class="card-label clean">Clean Packages</div>
            </div>
        </div>
        
        <div class="findings">
            <h2>🚨 Detailed Findings</h2>
"@

    # Add Malicious Packages section
    if ($totalMalicious -gt 0) {
        $html += @"
            <div class="finding-section">
                <h3>🔴 Malicious Packages ($totalMalicious)</h3>
"@
        foreach ($package in $scanData.MaliciousPackagesFound) {
            $html += @"
                <div class="package-card malicious">
                    <div class="package-name">$($package.Name)</div>
                    <div class="package-version">Version: $($package.Version)</div>
                    <div class="package-path">$($package.Path)</div>
                    <div class="package-details">
"@
            foreach ($detail in $package.Details) {
                $html += "                        <div class='detail-item'>$detail</div>`n"
            }
            $html += @"
                    </div>
                </div>
"@
        }
        $html += "            </div>`n"
    } else {
        $html += @"
            <div class="finding-section">
                <h3>🔴 Malicious Packages</h3>
                <div class="no-findings">✅ No malicious packages detected</div>
            </div>
"@
    }

    # Add Suspicious Packages section
    if ($totalSuspicious -gt 0) {
        $html += @"
            <div class="finding-section">
                <h3>🟡 Suspicious Packages ($totalSuspicious)</h3>
"@
        foreach ($package in $scanData.SuspiciousPackagesFound) {
            $html += @"
                <div class="package-card suspicious">
                    <div class="package-name">$($package.Name)</div>
                    <div class="package-version">Version: $($package.Version)</div>
                    <div class="package-path">$($package.Path)</div>
                    <div class="package-details">
"@
            foreach ($detail in $package.Details) {
                $html += "                        <div class='detail-item'>$detail</div>`n"
            }
            $html += @"
                    </div>
                </div>
"@
        }
        $html += "            </div>`n"
    } else {
        $html += @"
            <div class="finding-section">
                <h3>🟡 Suspicious Packages</h3>
                <div class="no-findings">✅ No suspicious packages detected</div>
            </div>
"@
    }

    # Add Manual Check section
    if ($totalManualCheck -gt 0) {
        $html += @"
            <div class="finding-section">
                <h3>🟠 Packages Requiring Manual Check ($totalManualCheck)</h3>
"@
        foreach ($package in $scanData.RequireManualCheck) {
            $html += @"
                <div class="package-card manual-check">
                    <div class="package-name">$($package.Name)</div>
                    <div class="package-version">Version: $($package.Version)</div>
                    <div class="package-path">$($package.Path)</div>
                    <div class="package-details">
"@
            foreach ($detail in $package.Details) {
                $html += "                        <div class='detail-item'>$detail</div>`n"
            }
            $html += @"
                    </div>
                </div>
"@
        }
        $html += "            </div>`n"
    } else {
        $html += @"
            <div class="finding-section">
                <h3>🟠 Packages Requiring Manual Check</h3>
                <div class="no-findings">✅ No packages require manual verification</div>
            </div>
"@
    }

    $html += @"
        </div>
        
        <footer class="footer">
            <div>Crimson7 NPM Security Scanner | <a href="https://crimson7.io" style="color: #ffc107; text-decoration: none;">crimson7.io</a></div>
            <div class="timestamp">Report generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
        </footer>
    </div>
</body>
</html>
"@

    # Write HTML to file
    $html | Out-File -FilePath $HtmlPath -Encoding UTF8
    Write-Host "HTML report generated: $HtmlPath" -ForegroundColor Green
    
    # Try to open the report in default browser
    if ($IsWindows) {
        Start-Process $HtmlPath
    } elseif ($IsMacOS) {
        & open $HtmlPath
    } elseif ($IsLinux) {
        & xdg-open $HtmlPath
    }
}

# Run the function
Generate-HTMLReport -JsonPath $JsonReportPath -HtmlPath $OutputPath