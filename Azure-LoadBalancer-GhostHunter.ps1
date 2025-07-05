#Requires -Module Az.Accounts, Az.Network, Az.Resources
<#
.SYNOPSIS
    LoadBalancer-GhostHunter - Hunt down forgotten and unused Azure Load Balancers
    
.DESCRIPTION
    This CloudCostChefs-style script scans all Azure subscriptions to identify "ghost" load balancers
    that are consuming resources but not actually serving traffic. Perfect for cost optimization!
    
.NOTES
    Author: CloudCostChefs
    Version: 1.0
    Requires: Az PowerShell Module
    
.EXAMPLE
    .\LoadBalancer-GhostHunter.ps1
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Path for CSV export")]
    [string]$CsvPath = "GhostLoadBalancers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(HelpMessage="Path for HTML report")]
    [string]$HtmlPath = "GhostLoadBalancers_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    
    [Parameter(HelpMessage="Only check specific subscription IDs")]
    [string[]]$SubscriptionIds
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
    Write-ColorOutput "║                          🔍 LoadBalancer-GhostHunter 🔍                      ║" -Color $script:Colors.Header
    Write-ColorOutput "║                              CloudCostChefs Edition                            ║" -Color $script:Colors.Header
    Write-ColorOutput "║                        Hunt down those forgotten LBs!                        ║" -Color $script:Colors.Header
    Write-ColorOutput "╚═══════════════════════════════════════════════════════════════════════════════╝" -Color $script:Colors.Header
    Write-Host ""
}

function Test-LoadBalancerHealth {
    param(
        [object]$LoadBalancer,
        [string]$SubscriptionName,
        [string]$ResourceGroupName
    )
    
    try {
        $ghostScore = 0
        $ghostReasons = @()
        $monthlyEstimatedCost = 0
        
        # Safely get properties with null checks
        $backendPools = if ($LoadBalancer.BackendAddressPools) { $LoadBalancer.BackendAddressPools } else { @() }
        $lbRules = if ($LoadBalancer.LoadBalancingRules) { $LoadBalancer.LoadBalancingRules } else { @() }
        $inboundNatRules = if ($LoadBalancer.InboundNatRules) { $LoadBalancer.InboundNatRules } else { @() }
        $frontendIPs = if ($LoadBalancer.FrontendIpConfigurations) { $LoadBalancer.FrontendIpConfigurations } else { @() }
        $healthProbes = if ($LoadBalancer.Probes) { $LoadBalancer.Probes } else { @() }
        $skuName = if ($LoadBalancer.Sku -and $LoadBalancer.Sku.Name) { $LoadBalancer.Sku.Name } else { "Unknown" }
        $lbTags = if ($LoadBalancer.Tags) { $LoadBalancer.Tags } else { @{} }
        
        # Check backend pools
        if ($backendPools.Count -eq 0) {
            $ghostScore += 50
            $ghostReasons += "No backend pools configured"
        } else {
            $emptyPools = $backendPools | Where-Object { 
                $backendIpCount = if ($_.BackendIpConfigurations) { $_.BackendIpConfigurations.Count } else { 0 }
                $backendAddressCount = if ($_.LoadBalancerBackendAddresses) { $_.LoadBalancerBackendAddresses.Count } else { 0 }
                return ($backendIpCount -eq 0 -and $backendAddressCount -eq 0)
            }
            
            if ($emptyPools.Count -eq $backendPools.Count) {
                $ghostScore += 45
                $ghostReasons += "All backend pools are empty"
            } elseif ($emptyPools.Count -gt 0) {
                $ghostScore += 25
                $ghostReasons += "Some backend pools are empty ($($emptyPools.Count)/$($backendPools.Count))"
            }
        }
        
        # Check load balancing rules
        if ($lbRules.Count -eq 0) {
            $ghostScore += 30
            $ghostReasons += "No load balancing rules configured"
        }
        
        # Check inbound NAT rules
        if ($inboundNatRules.Count -eq 0) {
            $ghostScore += 10
            $ghostReasons += "No inbound NAT rules configured"
        }
        
        # Check frontend IP configurations
        if ($frontendIPs.Count -eq 0) {
            $ghostScore += 40
            $ghostReasons += "No frontend IP configurations"
        } else {
            # Check for unused frontend IPs
            $unusedFrontends = $frontendIPs | Where-Object {
                $lbRuleCount = if ($_.LoadBalancingRules) { $_.LoadBalancingRules.Count } else { 0 }
                $natRuleCount = if ($_.InboundNatRules) { $_.InboundNatRules.Count } else { 0 }
                $natPoolCount = if ($_.InboundNatPools) { $_.InboundNatPools.Count } else { 0 }
                
                return ($lbRuleCount -eq 0 -and $natRuleCount -eq 0 -and $natPoolCount -eq 0)
            }
            
            if ($unusedFrontends.Count -gt 0) {
                $ghostScore += 15
                $ghostReasons += "Has unused frontend IP configurations ($($unusedFrontends.Count)/$($frontendIPs.Count))"
            }
        }
        
        # Check health probes
        if ($healthProbes.Count -eq 0) {
            $ghostScore += 20
            $ghostReasons += "No health probes configured"
        }
        
        # Estimate monthly cost based on LB type and configuration
        if ($skuName -eq "Standard") {
            $monthlyEstimatedCost = 22.56 # Standard LB base cost per month
            # Add rule costs
            $ruleCount = ($lbRules.Count + $inboundNatRules.Count)
            if ($ruleCount -gt 5) {
                $monthlyEstimatedCost += ($ruleCount - 5) * 2.70
            }
        } else {
            $monthlyEstimatedCost = 18.25 # Basic LB estimated cost
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
        
        # Count empty backend pools safely
        $emptyBackendPoolCount = 0
        if ($backendPools.Count -gt 0) {
            $emptyBackendPoolCount = ($backendPools | Where-Object { 
                $backendIpCount = if ($_.BackendIpConfigurations) { $_.BackendIpConfigurations.Count } else { 0 }
                $backendAddressCount = if ($_.LoadBalancerBackendAddresses) { $_.LoadBalancerBackendAddresses.Count } else { 0 }
                return ($backendIpCount -eq 0 -and $backendAddressCount -eq 0)
            }).Count
        }
        
        # Format tags safely
        $tagsString = ""
        if ($lbTags.Count -gt 0) {
            $tagsString = ($lbTags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "
        }
        
        # Collect detailed information for CSV export
        $backendPoolDetails = @()
        if ($backendPools.Count -gt 0) {
            foreach ($pool in $backendPools) {
                $memberCount = 0
                if ($pool.BackendIpConfigurations) { $memberCount += $pool.BackendIpConfigurations.Count }
                if ($pool.LoadBalancerBackendAddresses) { $memberCount += $pool.LoadBalancerBackendAddresses.Count }
                $backendPoolDetails += "$($pool.Name):$memberCount members"
            }
        }
        
        $ruleDetails = @()
        if ($lbRules.Count -gt 0) {
            foreach ($rule in $lbRules) {
                $frontendPort = if ($rule.FrontendPort) { $rule.FrontendPort } else { "Unknown" }
                $backendPort = if ($rule.BackendPort) { $rule.BackendPort } else { "Unknown" }
                $protocol = if ($rule.Protocol) { $rule.Protocol } else { "Unknown" }
                $ruleDetails += "$($rule.Name):$protocol $frontendPort->$backendPort"
            }
        }
        
        $frontendIPDetails = @()
        if ($frontendIPs.Count -gt 0) {
            foreach ($frontend in $frontendIPs) {
                $ipType = "Unknown"
                if ($frontend.PrivateIpAddress) { $ipType = "Private:$($frontend.PrivateIpAddress)" }
                elseif ($frontend.PublicIpAddress) { $ipType = "Public" }
                $frontendIPDetails += "$($frontend.Name):$ipType"
            }
        }
        
        $probeDetails = @()
        if ($healthProbes.Count -gt 0) {
            foreach ($probe in $healthProbes) {
                $port = if ($probe.Port) { $probe.Port } else { "Unknown" }
                $protocol = if ($probe.Protocol) { $probe.Protocol } else { "Unknown" }
                $interval = if ($probe.IntervalInSeconds) { $probe.IntervalInSeconds } else { "Unknown" }
                $probeDetails += "$($probe.Name):$protocol port $port every ${interval}s"
            }
        }
        
        return @{
            LoadBalancerName = if ($LoadBalancer.Name) { $LoadBalancer.Name } else { "Unknown" }
            ResourceGroup = $ResourceGroupName
            Subscription = $SubscriptionName
            Location = if ($LoadBalancer.Location) { $LoadBalancer.Location } else { "Unknown" }
            SKU = $skuName
            GhostScore = $ghostScore
            GhostStatus = $ghostStatus
            GhostReasons = ($ghostReasons -join "; ")
            BackendPoolCount = $backendPools.Count
            EmptyBackendPools = $emptyBackendPoolCount
            LoadBalancingRuleCount = $lbRules.Count
            InboundNatRuleCount = $inboundNatRules.Count
            FrontendIPCount = $frontendIPs.Count
            HealthProbeCount = $healthProbes.Count
            ResourceId = if ($LoadBalancer.Id) { $LoadBalancer.Id } else { "Unknown" }
            Tags = $tagsString
            # Detailed information for CSV
            BackendPoolDetails = ($backendPoolDetails -join "; ")
            LoadBalancingRuleDetails = ($ruleDetails -join "; ")
            FrontendIPDetails = ($frontendIPDetails -join "; ")
            HealthProbeDetails = ($probeDetails -join "; ")
        }
    }
    catch {
        Write-ColorOutput "         ⚠️ Error analyzing load balancer: $($_.Exception.Message)" -Color $script:Colors.Warning
        
        # Return minimal data structure on error
        return @{
            LoadBalancerName = if ($LoadBalancer.Name) { $LoadBalancer.Name } else { "Unknown" }
            ResourceGroup = $ResourceGroupName
            Subscription = $SubscriptionName
            Location = if ($LoadBalancer.Location) { $LoadBalancer.Location } else { "Unknown" }
            SKU = "Unknown"
            GhostScore = 0
            GhostStatus = "❌ ANALYSIS FAILED"
            GhostReasons = "Error during analysis: $($_.Exception.Message)"
            BackendPoolCount = 0
            EmptyBackendPools = 0
            LoadBalancingRuleCount = 0
            InboundNatRuleCount = 0
            FrontendIPCount = 0
            HealthProbeCount = 0
            ResourceId = if ($LoadBalancer.Id) { $LoadBalancer.Id } else { "Unknown" }
            Tags = ""
            # Detailed information for CSV
            BackendPoolDetails = ""
            LoadBalancingRuleDetails = ""
            FrontendIPDetails = ""
            HealthProbeDetails = ""
        }
    }
}

function New-HtmlReport {
    param(
        [array]$AllLoadBalancers,
        [array]$SuspiciousLoadBalancers,
        [int]$TotalScanned,
        [int]$TotalGhosts,
        [string]$OutputPath
    )
    
    $reportDate = Get-Date -Format "MMMM dd, yyyy 'at' HH:mm"
    $subscriptionList = ($AllLoadBalancers | Select-Object -ExpandProperty Subscription -Unique) -join ", "
    
    # Calculate statistics
    $definiteGhosts = ($SuspiciousLoadBalancers | Where-Object { $_.GhostScore -ge 80 }).Count
    $likelyGhosts = ($SuspiciousLoadBalancers | Where-Object { $_.GhostScore -ge 60 -and $_.GhostScore -lt 80 }).Count
    $suspicious = ($SuspiciousLoadBalancers | Where-Object { $_.GhostScore -ge 40 -and $_.GhostScore -lt 60 }).Count
    
    # Group by subscription for charts
    $subscriptionStats = $SuspiciousLoadBalancers | Group-Object Subscription | ForEach-Object {
        @{
            Name = $_.Name
            Count = $_.Count
            Ghosts = ($_.Group | Where-Object { $_.GhostScore -ge 80 }).Count
        }
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔍 LoadBalancer Ghost Hunter Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
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
        
        .ghost { color: #e74c3c; }
        .suspicious { color: #f39c12; }
        .total { color: #3498db; }
        .clean { color: #27ae60; }
        
        .content {
            padding: 30px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #3498db;
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
            background: #34495e;
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
        
        .score-definite { background: #e74c3c; }
        .score-likely { background: #e67e22; }
        .score-suspicious { background: #f39c12; }
        
        .ghost-status {
            font-weight: bold;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.9em;
        }
        
        .status-definite { background: #ffebee; color: #c62828; }
        .status-likely { background: #fff3e0; color: #ef6c00; }
        .status-suspicious { background: #fffbf0; color: #f57c00; }
        
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
            background: #ecf0f1;
            padding: 20px;
            text-align: center;
            color: #7f8c8d;
            border-top: 1px solid #bdc3c7;
        }
        
        .no-ghosts {
            text-align: center;
            padding: 60px;
            color: #27ae60;
            font-size: 1.5em;
        }
        
        .metadata {
            background: #f8f9fa;
            padding: 20px;
            border-left: 4px solid #3498db;
            margin-bottom: 30px;
            border-radius: 0 8px 8px 0;
        }
        
        .metadata h3 {
            color: #2c3e50;
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
            <h1>🔍 LoadBalancer Ghost Hunter</h1>
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
                <p><strong>Subscriptions Scanned:</strong> $subscriptionList</p>
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
                            <th>Subscription</th>
                            <th>Resource Group</th>
                            <th>Location</th>
                            <th>SKU</th>
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
            if ($ghost.BackendPoolDetails) { $configDetails += "Backend: $($ghost.BackendPoolDetails)" }
            if ($ghost.LoadBalancingRuleDetails) { $configDetails += "Rules: $($ghost.LoadBalancingRuleDetails)" }
            if ($ghost.FrontendIPDetails) { $configDetails += "Frontend: $($ghost.FrontendIPDetails)" }
            if ($ghost.HealthProbeDetails) { $configDetails += "Probes: $($ghost.HealthProbeDetails)" }
            
            $configText = if ($configDetails.Count -gt 0) { $configDetails -join "<br>" } else { "No configuration details available" }
            
            $html += @"
                        <tr>
                            <td><strong>$($ghost.LoadBalancerName)</strong></td>
                            <td>$($ghost.Subscription)</td>
                            <td>$($ghost.ResourceGroup)</td>
                            <td>$($ghost.Location)</td>
                            <td>$($ghost.SKU)</td>
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
                <p>No suspicious load balancers were found in your environment.</p>
                <p>All load balancers appear to be properly configured and in use.</p>
            </div>
"@
    }
    
    $html += @"
        </div>
        
        <div class="footer">
            <p>Generated by LoadBalancer Ghost Hunter - CloudCostChefs Edition</p>
            <p>Report created on $reportDate</p>
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}
function Get-AllSubscriptions {
    try {
        if ($SubscriptionIds) {
            Write-ColorOutput "🔍 Using specified subscription IDs..." -Color $script:Colors.Info
            $subscriptions = @()
            foreach ($subId in $SubscriptionIds) {
                try {
                    $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction Stop
                    $subscriptions += $sub
                } catch {
                    Write-ColorOutput "⚠️ Could not find subscription: $subId" -Color $script:Colors.Warning
                }
            }
            return $subscriptions
        } else {
            Write-ColorOutput "🔍 Discovering all available subscriptions..." -Color $script:Colors.Info
            return Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
        }
    } catch {
        Write-ColorOutput "❌ Error getting subscriptions: $($_.Exception.Message)" -Color $script:Colors.Error
        return @()
    }
}

function Start-GhostHunt {
    Show-Banner
    
    # Check if logged in to Azure
    $context = Get-AzContext
    if (-not $context) {
        Write-ColorOutput "🔐 Please login to Azure first..." -Color $script:Colors.Warning
        Connect-AzAccount
    }
    
    Write-ColorOutput "👤 Logged in as: $($context.Account.Id)" -Color $script:Colors.Info
    Write-Host ""
    
    # Get all subscriptions
    $subscriptions = Get-AllSubscriptions
    if ($subscriptions.Count -eq 0) {
        Write-ColorOutput "❌ No subscriptions found!" -Color $script:Colors.Error
        return
    }
    
    Write-ColorOutput "🔍 Found $($subscriptions.Count) subscription(s) to scan" -Color $script:Colors.Success
    Write-Host ""
    
    $allGhostLoadBalancers = @()
    $totalLoadBalancers = 0
    $totalGhosts = 0
    
    foreach ($subscription in $subscriptions) {
        Write-ColorOutput "🔄 Scanning subscription: $($subscription.Name)" -Color $script:Colors.Info
        
        try {
            # Set subscription context
            Set-AzContext -Subscription $subscription.Id | Out-Null
            
            # Get all load balancers in this subscription
            $loadBalancers = Get-AzLoadBalancer
            $totalLoadBalancers += $loadBalancers.Count
            
            if ($loadBalancers.Count -eq 0) {
                Write-ColorOutput "   ℹ️ No load balancers found in this subscription" -Color $script:Colors.Info
                continue
            }
            
            Write-ColorOutput "   📊 Found $($loadBalancers.Count) load balancer(s)" -Color $script:Colors.Info
            
            foreach ($lb in $loadBalancers) {
                try {
                    $lbName = if ($lb.Name) { $lb.Name } else { "Unknown-LB" }
                    Write-ColorOutput "      🔍 Analyzing: $lbName" -Color $script:Colors.Info
                    
                    # Get resource group name safely
                    $resourceGroupName = if ($lb.ResourceGroupName) { $lb.ResourceGroupName } else { "Unknown" }
                    
                    # Analyze the load balancer
                    $analysis = Test-LoadBalancerHealth -LoadBalancer $lb -SubscriptionName $subscription.Name -ResourceGroupName $resourceGroupName
                    
                    # Check if this is a ghost
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
                }
                catch {
                    $lbName = if ($lb.Name) { $lb.Name } else { "Unknown-LB" }
                    Write-ColorOutput "         ❌ Failed to analyze $lbName : $($_.Exception.Message)" -Color $script:Colors.Error
                    
                    # Add a minimal entry for failed analysis
                    $failedAnalysis = @{
                        LoadBalancerName = $lbName
                        ResourceGroup = if ($lb.ResourceGroupName) { $lb.ResourceGroupName } else { "Unknown" }
                        Subscription = $subscription.Name
                        Location = if ($lb.Location) { $lb.Location } else { "Unknown" }
                        SKU = "Unknown"
                        GhostScore = 0
                        GhostStatus = "❌ ANALYSIS FAILED"
                        GhostReasons = "Failed to analyze: $($_.Exception.Message)"
                        BackendPoolCount = 0
                        EmptyBackendPools = 0
                        LoadBalancingRuleCount = 0
                        InboundNatRuleCount = 0
                        FrontendIPCount = 0
                        HealthProbeCount = 0
                        ResourceId = if ($lb.Id) { $lb.Id } else { "Unknown" }
                        Tags = ""
                        # Detailed information for CSV
                        BackendPoolDetails = ""
                        LoadBalancingRuleDetails = ""
                        FrontendIPDetails = ""
                        HealthProbeDetails = ""
                    }
                    $allGhostLoadBalancers += $failedAnalysis
                }
            }
            
        } catch {
            Write-ColorOutput "   ❌ Error scanning subscription: $($_.Exception.Message)" -Color $script:Colors.Error
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
    
    # Calculate total waste cost safely - only include objects with valid cost data
    $validCostLBs = $suspiciousLBs | Where-Object { 
        $_.PSObject.Properties['EstimatedMonthlyCost'] -and 
        $_.EstimatedMonthlyCost -is [double] -and 
        $_.EstimatedMonthlyCost -gt 0 
    }
    
    $totalWastedCost = 0
    if ($validCostLBs.Count -gt 0) {
        $totalWastedCost = ($validCostLBs | Measure-Object -Property EstimatedMonthlyCost -Sum).Sum
    }
    
    if ($totalWastedCost -gt 0) {
        Write-ColorOutput "💰 Estimated Monthly Waste: ${totalWastedCost:N2}" -Color $script:Colors.Warning
        Write-ColorOutput "💰 Estimated Annual Waste: ${($totalWastedCost * 12):N2}" -Color $script:Colors.Warning
    } elseif ($suspiciousLBs.Count -gt 0) {
        Write-ColorOutput "💰 Cost calculation unavailable for some load balancers" -Color $script:Colors.Warning
    }
    
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
            Write-ColorOutput "   📍 Location: $($ghost.Subscription) / $($ghost.ResourceGroup) / $($ghost.Location)" -Color $script:Colors.Info
            Write-ColorOutput "   📊 Ghost Score: $($ghost.GhostScore)/100" -Color $script:Colors.Warning
            Write-ColorOutput "   🔍 Issues: $($ghost.GhostReasons)" -Color $script:Colors.Error
            Write-ColorOutput "   🏷️ SKU: $($ghost.SKU)" -Color $script:Colors.Info
            
            if ($ghost.Tags) {
                Write-ColorOutput "   🏷️ Tags: $($ghost.Tags)" -Color $script:Colors.Info
            }
            
            Write-Host ""
        }
    }
    
    # Automatically export only suspicious load balancers to CSV with full detailed information
    try {
        # Filter for suspicious load balancers only (Ghost Score >= 40)
        $suspiciousLBs = $allGhostLoadBalancers | Where-Object { $_.GhostScore -ge 40 }
        
        if ($suspiciousLBs.Count -gt 0) {
            Write-ColorOutput "🔍 Debug: Found $($suspiciousLBs.Count) suspicious load balancers to export" -Color $script:Colors.Info
            
            # Debug: Show first suspicious LB properties
            $firstLB = $suspiciousLBs[0]
            Write-ColorOutput "🔍 Debug: First LB properties: $($firstLB.PSObject.Properties.Name -join ', ')" -Color $script:Colors.Info
            
            # Convert hashtables to PSObjects for proper CSV export
            $exportData = @()
            foreach ($lb in $suspiciousLBs) {
                $exportData += New-Object PSObject -Property $lb
            }
            
            Write-ColorOutput "🔍 Debug: Created $($exportData.Count) PSObjects for export" -Color $script:Colors.Info
            
            # Export with explicit property selection
            $exportData | Select-Object LoadBalancerName, ResourceGroup, Subscription, Location, SKU, GhostScore, GhostStatus, GhostReasons, BackendPoolCount, EmptyBackendPools, LoadBalancingRuleCount, InboundNatRuleCount, FrontendIPCount, HealthProbeCount, ResourceId, Tags, BackendPoolDetails, LoadBalancingRuleDetails, FrontendIPDetails, HealthProbeDetails | Export-Csv -Path $CsvPath -NoTypeInformation
            
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
        $htmlContent = New-HtmlReport -AllLoadBalancers $allGhostLoadBalancers -SuspiciousLoadBalancers $suspiciousLBs -TotalScanned $totalLoadBalancers -TotalGhosts $totalGhosts -OutputPath $HtmlPath
        
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
    $results = Start-GhostHunt
}
