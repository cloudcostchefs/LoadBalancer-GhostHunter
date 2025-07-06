#Requires -Version 5.1
<#
.SYNOPSIS
    GCP LoadBalancer-GhostHunter - Hunt down forgotten and unused GCP Load Balancers
    
.DESCRIPTION
    This CloudCostChefs-style script scans all GCP projects to identify "ghost" load balancers
    that are consuming resources but not actually serving traffic. Perfect for cost optimization!
    Uses gcloud CLI for maximum compatibility.
    
.NOTES
    Author: CloudCostChefs
    Version: 1.0
    Requires: gcloud CLI installed and authenticated
    
.EXAMPLE
    .\GCP-LoadBalancer-GhostHunter.ps1
    
.EXAMPLE
    .\GCP-LoadBalancer-GhostHunter.ps1 -ProjectIds @("project-1", "project-2")
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Path for CSV export")]
    [string]$CsvPath = "GCP_GhostLoadBalancers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(HelpMessage="Path for HTML report")]
    [string]$HtmlPath = "GCP_GhostLoadBalancers_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    
    [Parameter(HelpMessage="Only check specific project IDs")]
    [string[]]$ProjectIds,
    
    [Parameter(HelpMessage="Specific regions to scan (default: all regions)")]
    [string[]]$Regions
)

# 🎨 CloudCostChefs Styling
$script:Colors = @{
    Header = "Cyan"
    Success = "Green" 
    Warning = "Yellow"
    Error = "Red"
    Info = "Blue"
    Ghost = "Magenta"
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewline
    )
    
    $params = @{
        Object = $Message
        ForegroundColor = $Color
    }
    if ($NoNewline) { $params.NoNewline = $true }
    
    Write-Host @params
}

function Show-Banner {
    Write-ColorOutput "╔═══════════════════════════════════════════════════════════════════════════════╗" -Color $script:Colors.Header
    Write-ColorOutput "║                         🔍 GCP LoadBalancer-GhostHunter 🔍                   ║" -Color $script:Colors.Header
    Write-ColorOutput "║                              CloudCostChefs Edition                            ║" -Color $script:Colors.Header
    Write-ColorOutput "║                        Hunt down those forgotten LBs!                        ║" -Color $script:Colors.Header
    Write-ColorOutput "╚═══════════════════════════════════════════════════════════════════════════════╝" -Color $script:Colors.Header
    Write-Host ""
}

function Invoke-GCloudCommand {
    param(
        [string]$Command,
        [switch]$AsJson,
        [switch]$SuppressErrors
    )
    
    try {
        if ($AsJson) {
            $result = Invoke-Expression "gcloud $Command --format=json" 2>$null
            if ($result) {
                return $result | ConvertFrom-Json
            }
        } else {
            $result = Invoke-Expression "gcloud $Command" 2>$null
            return $result
        }
    } catch {
        if (-not $SuppressErrors) {
            Write-ColorOutput "⚠️ gcloud command failed: $Command" -Color $script:Colors.Warning
        }
        return $null
    }
}

function Test-GCloudAuth {
    try {
        $authList = Invoke-GCloudCommand "auth list --filter=status:ACTIVE" -SuppressErrors
        if ($authList -and $authList.Count -gt 0) {
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

function Get-AllGCPProjects {
    try {
        if ($ProjectIds) {
            Write-ColorOutput "🔍 Using specified project IDs..." -Color $script:Colors.Info
            $projects = @()
            foreach ($projectId in $ProjectIds) {
                try {
                    $project = Invoke-GCloudCommand "projects describe $projectId" -AsJson
                    if ($project -and $project.lifecycleState -eq "ACTIVE") {
                        $projects += @{
                            ProjectId = $project.projectId
                            Name = $project.name
                            ProjectNumber = $project.projectNumber
                        }
                    }
                } catch {
                    Write-ColorOutput "⚠️ Could not access project: $projectId" -Color $script:Colors.Warning
                }
            }
            return $projects
        } else {
            Write-ColorOutput "🔍 Discovering all available projects..." -Color $script:Colors.Info
            $allProjects = Invoke-GCloudCommand "projects list" -AsJson
            $activeProjects = @()
            if ($allProjects) {
                foreach ($project in $allProjects) {
                    if ($project.lifecycleState -eq "ACTIVE") {
                        $activeProjects += @{
                            ProjectId = $project.projectId
                            Name = $project.name
                            ProjectNumber = $project.projectNumber
                        }
                    }
                }
            }
            return $activeProjects
        }
    } catch {
        Write-ColorOutput "❌ Error getting projects: $($_.Exception.Message)" -Color $script:Colors.Error
        Write-ColorOutput "💡 Make sure you're authenticated with: gcloud auth login" -Color $script:Colors.Info
        return @()
    }
}

function Get-GCPRegions {
    if ($Regions) {
        return $Regions
    } else {
        # Common GCP regions - you can expand this list
        return @(
            "us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
            "europe-north1", "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6",
            "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
            "asia-south1", "asia-southeast1", "asia-southeast2",
            "australia-southeast1", "southamerica-east1"
        )
    }
}

function Test-GCPLoadBalancerHealth {
    param(
        [object]$LoadBalancer,
        [string]$ProjectName,
        [string]$Region,
        [string]$LoadBalancerType
    )
    
    try {
        $ghostScore = 0
        $ghostReasons = @()
        
        $lbName = if ($LoadBalancer.name) { $LoadBalancer.name } else { "Unknown" }
        $lbDescription = if ($LoadBalancer.description) { $LoadBalancer.description } else { "No description" }
        
        # Get backend services and target pools based on type
        $backendServices = @()
        $targetPools = @()
        $backendCount = 0
        
        if ($LoadBalancerType -eq "Global-HTTP(S)") {
            # Global Load Balancer - check backend services
            if ($LoadBalancer.target) {
                $targetName = ($LoadBalancer.target -split '/')[-1]
                try {
                    # Try to get target HTTP proxy first
                    $targetProxy = Invoke-GCloudCommand "compute target-http-proxies describe $targetName --project=$ProjectName" -AsJson -SuppressErrors
                    if (-not $targetProxy) {
                        # Try HTTPS proxy
                        $targetProxy = Invoke-GCloudCommand "compute target-https-proxies describe $targetName --project=$ProjectName" -AsJson -SuppressErrors
                    }
                    
                    if ($targetProxy -and $targetProxy.urlMap) {
                        $urlMapName = ($targetProxy.urlMap -split '/')[-1]
                        $urlMap = Invoke-GCloudCommand "compute url-maps describe $urlMapName --project=$ProjectName" -AsJson -SuppressErrors
                        
                        if ($urlMap -and $urlMap.defaultService) {
                            $backendServiceName = ($urlMap.defaultService -split '/')[-1]
                            $backendService = Invoke-GCloudCommand "compute backend-services describe $backendServiceName --project=$ProjectName" -AsJson -SuppressErrors
                            if ($backendService) {
                                $backendServices += $backendService
                                $backendCount = if ($backendService.backends) { $backendService.backends.Count } else { 0 }
                            }
                        }
                    }
                } catch {
                    Write-ColorOutput "         ⚠️ Could not analyze global LB target: $($_.Exception.Message)" -Color $script:Colors.Warning
                }
            }
            
            if ($backendServices.Count -eq 0) {
                $ghostScore += 50
                $ghostReasons += "No backend services configured"
            } elseif ($backendCount -eq 0) {
                $ghostScore += 45
                $ghostReasons += "Backend service has no backends"
            }
            
        } elseif ($LoadBalancerType -eq "Regional-Network" -or $LoadBalancerType -eq "Regional-Internal") {
            # Regional Load Balancer - check backend services or target pools
            if ($LoadBalancer.backendService) {
                $backendServiceName = ($LoadBalancer.backendService -split '/')[-1]
                try {
                    $backendService = Invoke-GCloudCommand "compute backend-services describe $backendServiceName --region=$Region --project=$ProjectName" -AsJson -SuppressErrors
                    if ($backendService) {
                        $backendServices += $backendService
                        $backendCount = if ($backendService.backends) { $backendService.backends.Count } else { 0 }
                    }
                } catch {
                    Write-ColorOutput "         ⚠️ Could not get regional backend service: $($_.Exception.Message)" -Color $script:Colors.Warning
                }
            }
            
            if ($LoadBalancer.target) {
                $targetName = ($LoadBalancer.target -split '/')[-1]
                try {
                    $targetPool = Invoke-GCloudCommand "compute target-pools describe $targetName --region=$Region --project=$ProjectName" -AsJson -SuppressErrors
                    if ($targetPool) {
                        $targetPools += $targetPool
                        $backendCount += if ($targetPool.instances) { $targetPool.instances.Count } else { 0 }
                    }
                } catch {
                    Write-ColorOutput "         ⚠️ Could not get target pool: $($_.Exception.Message)" -Color $script:Colors.Warning
                }
            }
            
            if ($backendServices.Count -eq 0 -and $targetPools.Count -eq 0) {
                $ghostScore += 50
                $ghostReasons += "No backend services or target pools configured"
            } elseif ($backendCount -eq 0) {
                $ghostScore += 45
                $ghostReasons += "All backend services/target pools are empty"
            }
        }
        
        # Check IP address allocation
        $ipAddress = if ($LoadBalancer.IPAddress) { $LoadBalancer.IPAddress } else { "Not allocated" }
        if ($ipAddress -eq "Not allocated" -or $ipAddress -eq "") {
            $ghostScore += 15
            $ghostReasons += "No IP address allocated"
        }
        
        # Check port range
        $portRange = if ($LoadBalancer.portRange) { $LoadBalancer.portRange } else { "Not specified" }
        if ($portRange -eq "Not specified" -or $portRange -eq "") {
            $ghostScore += 20
            $ghostReasons += "No port range specified"
        }
        
        # Check load balancing scheme
        $loadBalancingScheme = if ($LoadBalancer.loadBalancingScheme) { $LoadBalancer.loadBalancingScheme } else { "EXTERNAL" }
        if ($loadBalancingScheme -eq "INTERNAL" -and $ghostScore -gt 30) {
            $ghostScore += 10
            $ghostReasons += "Internal load balancer with configuration issues"
        }
        
        # Check creation timestamp for age
        if ($LoadBalancer.creationTimestamp) {
            try {
                $createdDate = [DateTime]::Parse($LoadBalancer.creationTimestamp)
                $daysOld = ((Get-Date) - $createdDate).Days
                if ($daysOld -gt 30 -and $ghostScore -gt 40) {
                    $ghostScore += 10
                    $ghostReasons += "Created $daysOld days ago with issues"
                }
            } catch {
                # Ignore timestamp parsing errors
            }
        }
        
        # Determine ghost status
        $ghostStatus = if ($ghostScore -ge 80) { 
            "DEFINITE GHOST" 
        } elseif ($ghostScore -ge 60) { 
            "LIKELY GHOST" 
        } elseif ($ghostScore -ge 40) { 
            "SUSPICIOUS" 
        } elseif ($ghostScore -ge 20) { 
            "REVIEW NEEDED" 
        } else { 
            "ACTIVE" 
        }
        
        # Collect detailed information
        $backendDetails = @()
        foreach ($bs in $backendServices) {
            $bsBackendCount = if ($bs.backends) { $bs.backends.Count } else { 0 }
            $backendDetails += "$($bs.name):$bsBackendCount backends"
        }
        foreach ($tp in $targetPools) {
            $tpInstanceCount = if ($tp.instances) { $tp.instances.Count } else { 0 }
            $backendDetails += "$($tp.name):$tpInstanceCount instances"
        }
        
        $protocolDetails = @()
        $protocol = if ($LoadBalancer.IPProtocol) { $LoadBalancer.IPProtocol } else { "Unknown" }
        $protocolDetails += "$protocol"
        if ($portRange -ne "Not specified") {
            $protocolDetails += "Port: $portRange"
        }
        
        # Get labels (GCP equivalent of tags)
        $labelsString = ""
        if ($LoadBalancer.labels) {
            $labelArray = @()
            foreach ($label in $LoadBalancer.labels.PSObject.Properties) {
                $labelArray += "$($label.Name)=$($label.Value)"
            }
            $labelsString = $labelArray -join "; "
        }
        
        return @{
            LoadBalancerName = $lbName
            LoadBalancerType = $LoadBalancerType
            Project = $ProjectName
            Region = $Region
            IPAddress = $ipAddress
            LoadBalancingScheme = $loadBalancingScheme
            GhostScore = $ghostScore
            GhostStatus = $ghostStatus
            GhostReasons = ($ghostReasons -join "; ")
            BackendServiceCount = $backendServices.Count
            TargetPoolCount = $targetPools.Count
            Protocol = $protocol
            PortRange = $portRange
            CreationTimestamp = if ($LoadBalancer.creationTimestamp) { $LoadBalancer.creationTimestamp } else { "Unknown" }
            Description = $lbDescription
            LoadBalancerId = if ($LoadBalancer.id) { $LoadBalancer.id.ToString() } else { "Unknown" }
            SelfLink = if ($LoadBalancer.selfLink) { $LoadBalancer.selfLink } else { "Unknown" }
            Labels = $labelsString
            # Detailed information
            BackendDetails = ($backendDetails -join "; ")
            ProtocolDetails = ($protocolDetails -join "; ")
        }
        
    } catch {
        Write-ColorOutput "         ⚠️ Error analyzing load balancer: $($_.Exception.Message)" -Color $script:Colors.Warning
        
        return @{
            LoadBalancerName = if ($LoadBalancer.name) { $LoadBalancer.name } else { "Unknown" }
            LoadBalancerType = $LoadBalancerType
            Project = $ProjectName
            Region = $Region
            IPAddress = "Unknown"
            LoadBalancingScheme = "Unknown"
            GhostScore = 0
            GhostStatus = "ANALYSIS FAILED"
            GhostReasons = "Error during analysis: $($_.Exception.Message)"
            BackendServiceCount = 0
            TargetPoolCount = 0
            Protocol = "Unknown"
            PortRange = "Unknown"
            CreationTimestamp = "Unknown"
            Description = "Analysis failed"
            LoadBalancerId = if ($LoadBalancer.id) { $LoadBalancer.id.ToString() } else { "Unknown" }
            SelfLink = "Unknown"
            Labels = ""
            BackendDetails = ""
            ProtocolDetails = ""
        }
    }
}

function New-GCPHtmlReport {
    param(
        [array]$AllLoadBalancers,
        [array]$SuspiciousLoadBalancers,
        [int]$TotalScanned,
        [int]$TotalGhosts,
        [string]$OutputPath
    )
    
    $reportDate = Get-Date -Format "MMMM dd, yyyy 'at' HH:mm"
    $projectList = ($AllLoadBalancers | ForEach-Object { $_.Project } | Sort-Object -Unique) -join ", "
    
    # Calculate statistics
    $definiteGhosts = ($SuspiciousLoadBalancers | Where-Object { $_.GhostScore -ge 80 }).Count
    $likelyGhosts = ($SuspiciousLoadBalancers | Where-Object { $_.GhostScore -ge 60 -and $_.GhostScore -lt 80 }).Count
    $suspicious = ($SuspiciousLoadBalancers | Where-Object { $_.GhostScore -ge 40 -and $_.GhostScore -lt 60 }).Count
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔍 GCP LoadBalancer Ghost Hunter Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #4285f4 0%, #34a853 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1a73e8 0%, #137333 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .stat-label {
            color: #666;
            font-size: 1.1em;
        }
        
        .ghost { color: #ea4335; }
        .suspicious { color: #fbbc04; }
        .total { color: #4285f4; }
        .clean { color: #34a853; }
        
        .content {
            padding: 30px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #1a73e8;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #4285f4;
            font-size: 1.8em;
        }
        
        .ghost-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        
        .ghost-table th {
            background: #1a73e8;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }
        
        .ghost-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
            vertical-align: top;
        }
        
        .ghost-table tr:hover {
            background: #f8f9fa;
        }
        
        .ghost-score {
            font-weight: bold;
            padding: 5px 10px;
            border-radius: 20px;
            color: white;
            text-align: center;
            min-width: 60px;
        }
        
        .score-definite { background: #ea4335; }
        .score-likely { background: #f9ab00; }
        .score-suspicious { background: #fbbc04; color: #333; }
        
        .ghost-status {
            font-weight: bold;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.9em;
        }
        
        .status-definite { background: #fce8e6; color: #d93025; }
        .status-likely { background: #fef7e0; color: #e8710a; }
        .status-suspicious { background: #fefbf0; color: #ea8600; }
        
        .reasons {
            max-width: 300px;
            word-wrap: break-word;
        }
        
        .details {
            font-size: 0.9em;
            color: #666;
            max-width: 250px;
            word-wrap: break-word;
        }
        
        .footer {
            background: #f1f3f4;
            padding: 20px;
            text-align: center;
            color: #5f6368;
            border-top: 1px solid #dadce0;
        }
        
        .no-ghosts {
            text-align: center;
            padding: 60px;
            color: #34a853;
            font-size: 1.5em;
        }
        
        .metadata {
            background: #f8f9fa;
            padding: 20px;
            border-left: 4px solid #4285f4;
            margin-bottom: 30px;
            border-radius: 0 8px 8px 0;
        }
        
        .metadata h3 {
            color: #1a73e8;
            margin-bottom: 10px;
        }
        
        .metadata p {
            margin: 5px 0;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 GCP LoadBalancer Ghost Hunter</h1>
            <div class="subtitle">CloudCostChefs Edition - Hunt Report</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number total">$TotalScanned</div>
                <div class="stat-label">Total Load Balancers</div>
            </div>
            <div class="stat-card">
                <div class="stat-number ghost">$TotalGhosts</div>
                <div class="stat-label">Suspicious Load Balancers</div>
            </div>
            <div class="stat-card">
                <div class="stat-number ghost">$definiteGhosts</div>
                <div class="stat-label">Definite Ghosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number clean">$($TotalScanned - $TotalGhosts)</div>
                <div class="stat-label">Healthy Load Balancers</div>
            </div>
        </div>
        
        <div class="content">
            <div class="metadata">
                <h3>📊 Scan Details</h3>
                <p><strong>Report Generated:</strong> $reportDate</p>
                <p><strong>GCP Projects Scanned:</strong> $projectList</p>
                <p><strong>Analysis Criteria:</strong> Load balancers with Ghost Score ≥ 40 are considered suspicious</p>
            </div>
"@

    if ($SuspiciousLoadBalancers.Count -gt 0) {
        $html += @"
            <div class="section">
                <h2>👻 Suspicious Load Balancers Detected</h2>
                <table class="ghost-table">
                    <thead>
                        <tr>
                            <th>Load Balancer</th>
                            <th>Type</th>
                            <th>Project</th>
                            <th>Region</th>
                            <th>IP Address</th>
                            <th>Ghost Score</th>
                            <th>Status</th>
                            <th>Issues Found</th>
                            <th>Configuration Details</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($ghost in ($SuspiciousLoadBalancers | Sort-Object GhostScore -Descending)) {
            $scoreClass = switch ($ghost.GhostScore) {
                { $_ -ge 80 } { "score-definite" }
                { $_ -ge 60 } { "score-likely" }
                default { "score-suspicious" }
            }
            
            $statusClass = switch ($ghost.GhostScore) {
                { $_ -ge 80 } { "status-definite" }
                { $_ -ge 60 } { "status-likely" }
                default { "status-suspicious" }
            }
            
            $configDetails = @()
            if ($ghost.BackendDetails) { $configDetails += "Backends: $($ghost.BackendDetails)" }
            if ($ghost.ProtocolDetails) { $configDetails += "Protocol: $($ghost.ProtocolDetails)" }
            if ($ghost.LoadBalancingScheme) { $configDetails += "Scheme: $($ghost.LoadBalancingScheme)" }
            
            $configText = if ($configDetails.Count -gt 0) { $configDetails -join "<br>" } else { "No configuration details available" }
            
            $html += @"
                        <tr>
                            <td><strong>$($ghost.LoadBalancerName)</strong></td>
                            <td>$($ghost.LoadBalancerType)</td>
                            <td>$($ghost.Project)</td>
                            <td>$($ghost.Region)</td>
                            <td>$($ghost.IPAddress)</td>
                            <td><span class="ghost-score $scoreClass">$($ghost.GhostScore)</span></td>
                            <td><span class="ghost-status $statusClass">$($ghost.GhostStatus)</span></td>
                            <td class="reasons">$($ghost.GhostReasons)</td>
                            <td class="details">$configText</td>
                        </tr>
"@
        }
        
        $html += @"
                    </tbody>
                </table>
            </div>
"@
    } else {
        $html += @"
            <div class="no-ghosts">
                <h2>🎉 Congratulations!</h2>
                <p>No suspicious load balancers were found in your GCP environment.</p>
                <p>All load balancers appear to be properly configured and in use.</p>
            </div>
"@
    }
    
    $html += @"
        </div>
        
        <div class="footer">
            <p>Generated by GCP LoadBalancer Ghost Hunter - CloudCostChefs Edition</p>
            <p>Report created on $reportDate</p>
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

function Start-GCPGhostHunt {
    Show-Banner
    
    # Check if gcloud CLI is available
    try {
        $gcloudVersion = Invoke-Expression "gcloud version" 2>$null
        if (-not $gcloudVersion) {
            throw "gcloud not found"
        }
    } catch {
        Write-ColorOutput "❌ Google Cloud CLI (gcloud) not found!" -Color $script:Colors.Error
        Write-ColorOutput "💡 Please install it from: https://cloud.google.com/sdk/docs/install" -Color $script:Colors.Info
        return
    }
    
    # Check authentication
    if (-not (Test-GCloudAuth)) {
        Write-ColorOutput "❌ Not authenticated with GCP!" -Color $script:Colors.Error
        Write-ColorOutput "💡 Please run: gcloud auth login" -Color $script:Colors.Info
        return
    }
    
    # Get current project
    try {
        $currentProject = Invoke-GCloudCommand "config get-value project" -SuppressErrors
        if ($currentProject) {
            Write-ColorOutput "👤 Connected to GCP with default project: $currentProject" -Color $script:Colors.Info
        } else {
            Write-ColorOutput "👤 Connected to GCP (no default project set)" -Color $script:Colors.Info
        }
    } catch {
        Write-ColorOutput "👤 Connected to GCP" -Color $script:Colors.Info
    }
    
    Write-Host ""
    
    # Get all projects
    $projects = Get-AllGCPProjects
    if ($projects.Count -eq 0) {
        Write-ColorOutput "❌ No projects found!" -Color $script:Colors.Error
        return
    }
    
    Write-ColorOutput "🔍 Found $($projects.Count) project(s) to scan" -Color $script:Colors.Success
    Write-Host ""
    
    $allGhostLoadBalancers = @()
    $totalLoadBalancers = 0
    $totalGhosts = 0
    $regionsToScan = Get-GCPRegions
    
    foreach ($project in $projects) {
        Write-ColorOutput "🔄 Scanning project: $($project.Name) ($($project.ProjectId))" -Color $script:Colors.Info
        
        try {
            $projectLBCount = 0
            
            # Scan Global Load Balancers (HTTP/HTTPS)
            try {
                $globalForwardingRules = Invoke-GCloudCommand "compute forwarding-rules list --global --project=$($project.ProjectId)" -AsJson
                if ($globalForwardingRules) {
                    foreach ($rule in $globalForwardingRules) {
                        try {
                            Write-ColorOutput "      🔍 Analyzing Global LB: $($rule.name)" -Color $script:Colors.Info
                            
                            $analysis = Test-GCPLoadBalancerHealth -LoadBalancer $rule -ProjectName $project.ProjectId -Region "global" -LoadBalancerType "Global-HTTP(S)"
                            
                            # Display result
                            if ($analysis.GhostScore -ge 40) {
                                $totalGhosts++
                                $displayStatus = switch ($analysis.GhostScore) {
                                    { $_ -ge 80 } { "👻 DEFINITE GHOST" }
                                    { $_ -ge 60 } { "🔍 LIKELY GHOST" }
                                    { $_ -ge 40 } { "⚠️ SUSPICIOUS" }
                                    default { "📊 REVIEW NEEDED" }
                                }
                                Write-ColorOutput "         $displayStatus - Score: $($analysis.GhostScore)" -Color $script:Colors.Ghost
                            } else {
                                $displayStatus = if ($analysis.GhostScore -ge 20) { "📊 REVIEW NEEDED" } else { "✅ ACTIVE" }
                                Write-ColorOutput "         $displayStatus - Score: $($analysis.GhostScore)" -Color $script:Colors.Success
                            }
                            
                            $allGhostLoadBalancers += $analysis
                            $projectLBCount++
                            
                        } catch {
                            Write-ColorOutput "         ❌ Failed to analyze global LB $($rule.name): $($_.Exception.Message)" -Color $script:Colors.Error
                        }
                    }
                }
            } catch {
                Write-ColorOutput "   ⚠️ Could not list global forwarding rules: $($_.Exception.Message)" -Color $script:Colors.Warning
            }
            
            # Scan Regional Load Balancers
            foreach ($region in $regionsToScan) {
                try {
                    # Regional forwarding rules (Internal/External)
                    $regionalRules = Invoke-GCloudCommand "compute forwarding-rules list --regions=$region --project=$($project.ProjectId)" -AsJson -SuppressErrors
                    
                    if ($regionalRules) {
                        foreach ($rule in $regionalRules) {
                            try {
                                Write-ColorOutput "      🔍 Analyzing Regional LB: $($rule.name) ($region)" -Color $script:Colors.Info
                                
                                $lbType = if ($rule.loadBalancingScheme -eq "INTERNAL") { "Regional-Internal" } else { "Regional-Network" }
                                $analysis = Test-GCPLoadBalancerHealth -LoadBalancer $rule -ProjectName $project.ProjectId -Region $region -LoadBalancerType $lbType
                                
                                # Display result
                                if ($analysis.GhostScore -ge 40) {
                                    $totalGhosts++
                                    $displayStatus = switch ($analysis.GhostScore) {
                                        { $_ -ge 80 } { "👻 DEFINITE GHOST" }
                                        { $_ -ge 60 } { "🔍 LIKELY GHOST" }
                                        { $_ -ge 40 } { "⚠️ SUSPICIOUS" }
                                        default { "📊 REVIEW NEEDED" }
                                    }
                                    Write-ColorOutput "         $displayStatus - Score: $($analysis.GhostScore)" -Color $script:Colors.Ghost
                                } else {
                                    $displayStatus = if ($analysis.GhostScore -ge 20) { "📊 REVIEW NEEDED" } else { "✅ ACTIVE" }
                                    Write-ColorOutput "         $displayStatus - Score: $($analysis.GhostScore)" -Color $script:Colors.Success
                                }
                                
                                $allGhostLoadBalancers += $analysis
                                $projectLBCount++
                                
                            } catch {
                                Write-ColorOutput "         ❌ Failed to analyze regional LB $($rule.name): $($_.Exception.Message)" -Color $script:Colors.Error
                            }
                        }
                    }
                } catch {
                    # Silently skip regions where we don't have access or no resources exist
                }
            }
            
            $totalLoadBalancers += $projectLBCount
            
            if ($projectLBCount -eq 0) {
                Write-ColorOutput "   ℹ️ No load balancers found in this project" -Color $script:Colors.Info
            } else {
                Write-ColorOutput "   📊 Found $projectLBCount load balancer(s)" -Color $script:Colors.Info
            }
            
        } catch {
            Write-ColorOutput "   ❌ Error scanning project: $($_.Exception.Message)" -Color $script:Colors.Error
        }
        
        Write-Host ""
    }
    
    # Summary
    Write-ColorOutput "╔═══════════════════════════════════════════════════════════════════════════════╗" -Color $script:Colors.Header
    Write-ColorOutput "║                                   📊 HUNT SUMMARY                             ║" -Color $script:Colors.Header
    Write-ColorOutput "╚═══════════════════════════════════════════════════════════════════════════════╝" -Color $script:Colors.Header
    
    Write-ColorOutput "📊 Total Load Balancers Scanned: $totalLoadBalancers" -Color $script:Colors.Info
    Write-ColorOutput "👻 Potential Ghost Load Balancers: $totalGhosts" -Color $script:Colors.Ghost
    
    $suspiciousLBs = $allGhostLoadBalancers | Where-Object { $_.GhostScore -ge 40 }
    
    Write-Host ""
    
    # Show detailed results for ghosts
    if ($suspiciousLBs.Count -gt 0) {
        Write-ColorOutput "🔍 DETAILED GHOST ANALYSIS:" -Color $script:Colors.Ghost
        Write-ColorOutput "═══════════════════════════════════════════════════════════════════════════════" -Color $script:Colors.Header
        
        foreach ($ghost in $suspiciousLBs | Sort-Object GhostScore -Descending) {
            $displayStatus = switch ($ghost.GhostScore) {
                { $_ -ge 80 } { "👻 DEFINITE GHOST" }
                { $_ -ge 60 } { "🔍 LIKELY GHOST" }
                { $_ -ge 40 } { "⚠️ SUSPICIOUS" }
                default { "📊 REVIEW NEEDED" }
            }
            Write-ColorOutput "👻 $($ghost.LoadBalancerName) ($displayStatus)" -Color $script:Colors.Ghost
            Write-ColorOutput "   📍 Location: $($ghost.Project) / $($ghost.Region) / $($ghost.LoadBalancerType)" -Color $script:Colors.Info
            Write-ColorOutput "   📊 Ghost Score: $($ghost.GhostScore)/100" -Color $script:Colors.Warning
            Write-ColorOutput "   🔍 Issues: $($ghost.GhostReasons)" -Color $script:Colors.Error
            Write-ColorOutput "   🌐 IP Address: $($ghost.IPAddress)" -Color $script:Colors.Info
            Write-ColorOutput "   🏷️ Scheme: $($ghost.LoadBalancingScheme)" -Color $script:Colors.Info
            
            if ($ghost.Labels) {
                Write-ColorOutput "   🏷️ Labels: $($ghost.Labels)" -Color $script:Colors.Info
            }
            
            Write-Host ""
        }
    }
    
    # Export suspicious load balancers to CSV
    try {
        # Filter for suspicious load balancers only (Ghost Score >= 40)
        $suspiciousLBs = $allGhostLoadBalancers | Where-Object { $_.GhostScore -ge 40 }
        
        if ($suspiciousLBs.Count -gt 0) {
            Write-ColorOutput "🔍 Debug: Found $($suspiciousLBs.Count) suspicious load balancers to export" -Color $script:Colors.Info
            
            # Convert hashtables to PSObjects for proper CSV export
            $exportData = @()
            foreach ($lb in $suspiciousLBs) {
                $exportData += New-Object PSObject -Property $lb
            }
            
            Write-ColorOutput "🔍 Debug: Created $($exportData.Count) PSObjects for export" -Color $script:Colors.Info
            
            # Export with explicit property selection
            $exportData | Select-Object LoadBalancerName, LoadBalancerType, Project, Region, IPAddress, LoadBalancingScheme, GhostScore, GhostStatus, GhostReasons, BackendServiceCount, TargetPoolCount, Protocol, PortRange, CreationTimestamp, Description, LoadBalancerId, SelfLink, Labels, BackendDetails, ProtocolDetails | Export-Csv -Path $CsvPath -NoTypeInformation
            
            Write-ColorOutput "📄 Suspicious load balancers exported to: $CsvPath" -Color $script:Colors.Success
            Write-ColorOutput "📊 Exported $($suspiciousLBs.Count) suspicious load balancers (Ghost Score ≥ 40)" -Color $script:Colors.Warning
            Write-ColorOutput "💡 CSV includes full configuration details for analysis" -Color $script:Colors.Info
            
            # Verify file was created and has content
            if (Test-Path $CsvPath) {
                $fileSize = (Get-Item $CsvPath).Length
                Write-ColorOutput "✅ CSV file created successfully ($fileSize bytes)" -Color $script:Colors.Success
            } else {
                Write-ColorOutput "❌ CSV file was not created!" -Color $script:Colors.Error
            }
        } else {
            Write-ColorOutput "🎉 No suspicious load balancers found - no CSV export needed!" -Color $script:Colors.Success
        }
    } catch {
        Write-ColorOutput "❌ Failed to export CSV: $($_.Exception.Message)" -Color $script:Colors.Error
        Write-ColorOutput "🔍 Debug: Error details: $($_.Exception.ToString())" -Color $script:Colors.Error
    }
    
    # Generate HTML Report
    Write-Host ""
    Write-ColorOutput "📄 Generating HTML report..." -Color $script:Colors.Info
    try {
        $htmlContent = New-GCPHtmlReport -AllLoadBalancers $allGhostLoadBalancers -SuspiciousLoadBalancers $suspiciousLBs -TotalScanned $totalLoadBalancers -TotalGhosts $totalGhosts -OutputPath $HtmlPath
        
        $htmlContent | Out-File -FilePath $HtmlPath -Encoding UTF8
        
        Write-ColorOutput "📄 HTML report generated: $HtmlPath" -Color $script:Colors.Success
        
        # Verify HTML file was created and has content
        if (Test-Path $HtmlPath) {
            $htmlFileSize = (Get-Item $HtmlPath).Length
            Write-ColorOutput "✅ HTML report created successfully ($htmlFileSize bytes)" -Color $script:Colors.Success
            Write-ColorOutput "🌐 Open the HTML file in your browser to view the interactive report" -Color $script:Colors.Info
        } else {
            Write-ColorOutput "❌ HTML file was not created!" -Color $script:Colors.Error
        }
    } catch {
        Write-ColorOutput "❌ Failed to generate HTML report: $($_.Exception.Message)" -Color $script:Colors.Error
    }
    
    Write-ColorOutput "🎉 Ghost hunt complete!" -Color $script:Colors.Success
    
    return $allGhostLoadBalancers
}

# 🚀 Execute the ghost hunt
if ($MyInvocation.InvocationName -ne '.') {
    $results = Start-GCPGhostHunt
}
