<#
.SYNOPSIS
    Enhanced auditor for Conditional Access (CA) policy coverage for users in Entra ID (Azure AD).

.DESCRIPTION
    For each user, computes which Conditional Access policies target them based on:
      - Include/Exclude: Users, Groups (transitive), Directory Roles (transitive)
      - Include/Exclude Guests or External Users
      - Includes ALL policies (Enabled, Report-only, Disabled)
      - Identifies mailbox type (User, Shared, Room, Equipment, or N/A)
    It does NOT simulate sign-in-time conditions (device, platform, location, app, risk, auth context).
    Output is a detailed CSV showing exactly which policies are enforced for each user.

.REQUIREMENTS
    - PowerShell 7+ recommended (Windows PowerShell 5.1 works)
    - Microsoft Graph PowerShell SDK (specific submodules only)
      * Microsoft.Graph.Authentication
      * Microsoft.Graph.Users
      * Microsoft.Graph.Identity.SignIns
    - Exchange Online PowerShell Module (optional, for mailbox type detection)
      * ExchangeOnlineManagement
    - Permissions: Policy.Read.All, Directory.Read.All (RoleManagement.Read.Directory recommended)
    - Exchange Permissions: View-Only Recipients or Exchange Administrator (if checking mailbox types)

.PARAMETER OutputPath
    CSV output file path. Defaults to ".\CA_Coverage_<timestamp>.csv"

.PARAMETER UserTypes
    Which user types to include: Member, Guest, Both (default: Both)

.PARAMETER OnlyEnabledUsers
    If provided, restricts to users with accountEnabled = true (default: include all accounts)

.PARAMETER ExcludeUserFilterScriptBlock
    A script block to exclude users by your own rules.
    Receives a user object as param($user). Return $true to exclude, $false to include.
    Example: { param($u) $u.userPrincipalName -like "svc_*" }

.PARAMETER EmitMatrix
    If set, also emits a wide user x policy matrix CSV (may be large in big tenants).

.PARAMETER ShowPolicyDetails
    Include detailed policy information (controls, conditions) in the output.

.PARAMETER CheckMailboxType
    If set, connects to Exchange Online and checks mailbox type for each user.
    This will significantly increase runtime for large user sets.

.EXAMPLE
    .\Get-EntraCAPolicyCoverage.ps1

.EXAMPLE
    .\Get-EntraCAPolicyCoverage.ps1 -UserTypes Member -CheckMailboxType

.EXAMPLE
    .\Get-EntraCAPolicyCoverage.ps1 -OnlyEnabledUsers -EmitMatrix -ShowPolicyDetails -CheckMailboxType
#>

[CmdletBinding()]
param(
    [string]$OutputPath = $(Join-Path -Path (Get-Location) -ChildPath ("CA_Coverage_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))),

    [ValidateSet('Member','Guest','Both')]
    [string]$UserTypes = 'Both',

    [switch]$OnlyEnabledUsers,

    [ScriptBlock]$ExcludeUserFilterScriptBlock = { param($u) return $false },

    [switch]$EmitMatrix,

    [switch]$UseBeta, # Deprecated - kept for compatibility

    [switch]$ShowPolicyDetails,

    [switch]$CheckMailboxType
)

# Optional: Clear any previously loaded (meta) Graph modules to avoid function overflow
Remove-Module Microsoft.Graph -Force -ErrorAction SilentlyContinue
Remove-Module Microsoft.Graph.* -Force -ErrorAction SilentlyContinue

# Determine mailbox checking method (set default to Graph API)
$script:UseGraphForMailbox = $true

# --------------------------
# Helper: Ensure minimal Graph submodules
# --------------------------
function Ensure-GraphSubmodules {
    $required = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Identity.SignIns'
    )

    Write-Host "Checking Microsoft Graph PowerShell SDK modules..." -ForegroundColor Cyan
    
    foreach ($mod in $required) {
        $installedModule = Get-Module -ListAvailable -Name $mod | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $installedModule) {
            Write-Host "Module $mod not found. Installing for current user..." -ForegroundColor Yellow
            try {
                Install-Module $mod -Scope CurrentUser -Force -ErrorAction Stop
                Write-Host "Successfully installed $mod" -ForegroundColor Green
            } catch {
                Write-Error "Failed to install $mod. Please install manually and retry. $_"
                exit 1
            }
        } else {
            Write-Host "Found $mod version $($installedModule.Version)" -ForegroundColor Green
        }
    }

    foreach ($mod in $required) {
        try {
            Import-Module $mod -ErrorAction Stop
        } catch {
            Write-Error "Failed to import module $mod. $_"
            exit 1
        }
    }
    
    Write-Host "All required Graph modules loaded successfully." -ForegroundColor Green
}

# --------------------------
# Helper: Ensure Exchange Online module
# --------------------------
function Ensure-ExchangeOnlineModule {
    if (-not $CheckMailboxType) { return }
    
    Write-Host "Checking Exchange Online PowerShell module..." -ForegroundColor Cyan
    
    $exoModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $exoModule) {
        Write-Host "ExchangeOnlineManagement module not found. Installing for current user..." -ForegroundColor Yellow
        try {
            Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -ErrorAction Stop
            Write-Host "Successfully installed ExchangeOnlineManagement" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to install ExchangeOnlineManagement. Mailbox type checking will be skipped. $_"
            $script:CheckMailboxType = $false
            return
        }
    } else {
        Write-Host "Found ExchangeOnlineManagement version $($exoModule.Version)" -ForegroundColor Green
    }
    
    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        Write-Host "ExchangeOnlineManagement module loaded successfully." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to import ExchangeOnlineManagement. Mailbox type checking will be skipped. $_"
        $script:CheckMailboxType = $false
    }
}

# --------------------------
# Helper: Connect to Exchange Online
# --------------------------
function Connect-ExchangeOnlineIfNeeded {
    if (-not $CheckMailboxType) { 
        Write-Verbose "CheckMailboxType is false, skipping Exchange Online connection"
        return 
    }
    
    try {
        Write-Host "Checking Exchange Online connection status..." -ForegroundColor Cyan
        
        # Check if already connected
        $existingSession = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if ($existingSession) {
            Write-Host "Already connected to Exchange Online:" -ForegroundColor Green
            Write-Host "  Organization: $($existingSession.Organization)" -ForegroundColor Cyan
            Write-Host "  User: $($existingSession.UserPrincipalName)" -ForegroundColor Cyan
            
            # Test the connection with a simple command
            try {
                $testMailbox = Get-EXOMailbox -ResultSize 1 -ErrorAction Stop
                Write-Host "  Connection test: SUCCESS" -ForegroundColor Green
                return $true
            } catch {
                Write-Warning "Existing connection appears stale. Reconnecting..."
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        
        Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
        Write-Host "NOTE: You will be prompted for credentials if not already authenticated." -ForegroundColor Yellow
        Write-Host "Please sign in with an account that has Exchange Administrator or View-Only Recipients permissions." -ForegroundColor Yellow
        
        # Try to connect with InlineCredential to avoid WAM (Web Account Manager) issues
        # This fixes the "window handle must be configured" error
        try {
            Connect-ExchangeOnline -ShowBanner:$false -InlineCredential -ErrorAction Stop
        } catch {
            # If InlineCredential fails, try without it (for older module versions)
            Write-Verbose "InlineCredential failed, trying standard authentication..."
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
        
        # Verify connection worked
        $connectionInfo = Get-ConnectionInformation -ErrorAction Stop
        Write-Host "Successfully connected to Exchange Online!" -ForegroundColor Green
        Write-Host "  Organization: $($connectionInfo.Organization)" -ForegroundColor Cyan
        Write-Host "  User: $($connectionInfo.UserPrincipalName)" -ForegroundColor Cyan
        
        # Final test
        $testMailbox = Get-EXOMailbox -ResultSize 1 -ErrorAction Stop
        Write-Host "  Connection verified with test query." -ForegroundColor Green
        
        return $true
        
    } catch {
        Write-Host ""
        Write-Error "Failed to connect to Exchange Online!"
        Write-Host "Error details: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "Troubleshooting steps:" -ForegroundColor Yellow
        Write-Host "1. Ensure you have the ExchangeOnlineManagement module installed" -ForegroundColor Yellow
        Write-Host "2. Verify you have Exchange Administrator or View-Only Recipients permissions" -ForegroundColor Yellow
        Write-Host "3. Try running: Connect-ExchangeOnline manually first" -ForegroundColor Yellow
        Write-Host "4. Check if MFA is required for your account" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Mailbox type checking will be DISABLED for this run." -ForegroundColor Red
        Write-Host "The script will continue but AccountType and MailboxType columns will show 'Not Checked'." -ForegroundColor Yellow
        Write-Host ""
        
        $script:CheckMailboxType = $false
        return $false
    }
}

# --------------------------
# Helper: Get mailbox type for a user
# --------------------------
function Get-UserMailboxType {
    param([Parameter(Mandatory=$true)][string]$UserPrincipalName)
    
    if (-not $CheckMailboxType) { return "Not Checked" }
    
    try {
        $mailbox = Get-EXOMailbox -Identity $UserPrincipalName -ErrorAction SilentlyContinue -Properties RecipientTypeDetails
        
        if ($mailbox) {
            return $mailbox.RecipientTypeDetails
        } else {
            # No mailbox found - might be cloud-only account without mailbox
            return "No Mailbox"
        }
    } catch {
        # Handle various error scenarios
        if ($_.Exception.Message -like "*couldn't be found*" -or $_.Exception.Message -like "*not found*") {
            return "No Mailbox"
        } else {
            Write-Verbose "Error checking mailbox for $UserPrincipalName : $_"
            return "Error"
        }
    }
}

# --------------------------
# Helper: Get mailbox type using Microsoft Graph
# --------------------------
function Get-MailboxTypeViaGraph {
    param([Parameter(Mandatory=$true)][string]$UserId)
    
    try {
        # Query user's mailbox settings via Graph
        $uri = "https://graph.microsoft.com/v1.0/users/$UserId/mailboxSettings"
        $result = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
        
        # If we get a response, the user has a mailbox
        # We need additional properties to determine if it's shared
        $userDetails = Get-MgUser -UserId $UserId -Property "assignedLicenses,userType" -ErrorAction SilentlyContinue
        
        # Check if user has any licenses (shared mailboxes typically don't)
        if ($userDetails.AssignedLicenses.Count -eq 0) {
            return "SharedMailbox"  # Likely a shared mailbox
        } else {
            return "UserMailbox"
        }
    } catch {
        if ($_.Exception.Message -like "*MailboxNotEnabledForRESTAPI*" -or 
            $_.Exception.Message -like "*ResourceNotFound*" -or
            $_.Exception.Message -like "*ErrorItemNotFound*") {
            return "No Mailbox"
        } else {
            Write-Verbose "Error checking mailbox via Graph for user $UserId : $_"
            return "Unknown"
        }
    }
}

# --------------------------
# Helper: Batch get mailbox types (more efficient)
# --------------------------
function Get-MailboxTypesBatch {
    param([Parameter(Mandatory=$true)][array]$Users)
    
    if (-not $CheckMailboxType -or $Users.Count -eq 0) { 
        Write-Host "Mailbox type checking is disabled or no users to process." -ForegroundColor Yellow
        return @{}
    }
    
    # Use Graph API method if selected
    if ($script:UseGraphForMailbox) {
        Write-Host "Using Microsoft Graph API to check mailbox types for $($Users.Count) users..." -ForegroundColor Cyan
        Write-Host "Note: This method may not distinguish all mailbox types as precisely as Exchange Online." -ForegroundColor Yellow
        
        $mailboxTypes = @{}
        $userCount = 0
        $totalUsers = $Users.Count
        
        foreach ($user in $Users) {
            $userCount++
            if ($userCount % 10 -eq 0 -or $userCount -eq $totalUsers) {
                $percentComplete = [Math]::Round(($userCount / $totalUsers) * 100, 1)
                Write-Progress -Activity "Checking mailbox types via Graph API" -Status "Processing user $userCount of $totalUsers" -PercentComplete $percentComplete
            }
            
            try {
                # Check assignedLicenses to determine if it's likely a shared mailbox
                $userWithLicenses = Get-MgUser -UserId $user.Id -Property "assignedLicenses" -ErrorAction Stop
                
                if ($userWithLicenses.AssignedLicenses.Count -eq 0 -and $user.Mail) {
                    # No licenses but has email = likely shared mailbox
                    $mailboxTypes[$user.UserPrincipalName] = "SharedMailbox"
                } elseif ($userWithLicenses.AssignedLicenses.Count -gt 0) {
                    # Has licenses = regular user mailbox
                    $mailboxTypes[$user.UserPrincipalName] = "UserMailbox"
                } else {
                    # No licenses and no mail attribute
                    $mailboxTypes[$user.UserPrincipalName] = "No Mailbox"
                }
            } catch {
                Write-Verbose "Error checking user $($user.UserPrincipalName): $_"
                $mailboxTypes[$user.UserPrincipalName] = "Unknown"
            }
            
            # Small delay every 100 users to avoid throttling
            if ($userCount % 100 -eq 0) {
                Start-Sleep -Milliseconds 200
            }
        }
        
        Write-Progress -Activity "Checking mailbox types via Graph API" -Completed
        
        # Summary statistics
        $stats = $mailboxTypes.Values | Group-Object | Sort-Object Name
        Write-Host ""
        Write-Host "Mailbox type detection summary (via Graph API):" -ForegroundColor Cyan
        foreach ($stat in $stats) {
            Write-Host "  $($stat.Name): $($stat.Count)" -ForegroundColor Cyan
        }
        Write-Host "Total processed: $($mailboxTypes.Count) users" -ForegroundColor Green
        
        return $mailboxTypes
    }
    
    # Original Exchange Online method
    Write-Host "Retrieving mailbox information for $($Users.Count) users (this may take a while)..." -ForegroundColor Cyan
    
    # First, verify Exchange Online connection
    try {
        Write-Host "Testing Exchange Online connection..." -ForegroundColor Cyan
        $testMailbox = Get-EXOMailbox -ResultSize 1 -ErrorAction Stop
        Write-Host "Exchange Online connection verified successfully." -ForegroundColor Green
    } catch {
        Write-Error "Exchange Online connection test failed: $_"
        Write-Host "Unable to retrieve mailbox information. All accounts will be marked as 'Connection Failed'." -ForegroundColor Red
        $failedLookup = @{}
        foreach ($user in $Users) {
            $failedLookup[$user.UserPrincipalName] = "Connection Failed"
        }
        return $failedLookup
    }
    
    $mailboxTypes = @{}
    $batchSize = 50  # Reduced batch size for better reliability
    $batches = [Math]::Ceiling($Users.Count / $batchSize)
    
    Write-Host "Processing in $batches batches of up to $batchSize users each..." -ForegroundColor Cyan
    
    for ($i = 0; $i -lt $batches; $i++) {
        $startIdx = $i * $batchSize
        $endIdx = [Math]::Min(($startIdx + $batchSize - 1), ($Users.Count - 1))
        $batchUsers = $Users[$startIdx..$endIdx]
        
        $percentComplete = [Math]::Round((($i + 1) / $batches) * 100, 1)
        Write-Progress -Activity "Checking mailbox types" -Status "Processing batch $($i + 1) of $batches ($($batchUsers.Count) users)" -PercentComplete $percentComplete
        
        Write-Verbose "Batch $($i + 1): Processing users $startIdx to $endIdx"
        
        try {
            # Try to get all mailboxes with a filter approach
            $mailboxes = @()
            foreach ($user in $batchUsers) {
                try {
                    $mbx = Get-EXOMailbox -Identity $user.UserPrincipalName -Properties RecipientTypeDetails -ErrorAction Stop
                    if ($mbx) {
                        $mailboxes += $mbx
                        Write-Verbose "Found mailbox for $($user.UserPrincipalName): $($mbx.RecipientTypeDetails)"
                    }
                } catch {
                    if ($_.Exception.Message -like "*couldn't be found*" -or $_.Exception.Message -like "*not found*") {
                        $mailboxTypes[$user.UserPrincipalName] = "No Mailbox"
                        Write-Verbose "No mailbox found for $($user.UserPrincipalName)"
                    } else {
                        $mailboxTypes[$user.UserPrincipalName] = "Error"
                        Write-Verbose "Error checking $($user.UserPrincipalName): $_"
                    }
                }
            }
            
            # Create lookup dictionary for found mailboxes
            foreach ($mbx in $mailboxes) {
                $mailboxTypes[$mbx.UserPrincipalName] = $mbx.RecipientTypeDetails
            }
            
            # Mark any users not yet processed as "No Mailbox"
            foreach ($user in $batchUsers) {
                if (-not $mailboxTypes.ContainsKey($user.UserPrincipalName)) {
                    $mailboxTypes[$user.UserPrincipalName] = "No Mailbox"
                }
            }
            
            Write-Host "Batch $($i + 1)/$batches complete: Found $($mailboxes.Count) mailboxes out of $($batchUsers.Count) users" -ForegroundColor Green
            
        } catch {
            Write-Warning "Error processing batch $($i + 1): $_"
            # Mark all users in failed batch as "Error"
            foreach ($user in $batchUsers) {
                if (-not $mailboxTypes.ContainsKey($user.UserPrincipalName)) {
                    $mailboxTypes[$user.UserPrincipalName] = "Batch Error"
                }
            }
        }
        
        # Small delay to avoid throttling
        if ($i -lt ($batches - 1)) {
            Start-Sleep -Milliseconds 500
        }
    }
    
    Write-Progress -Activity "Checking mailbox types" -Completed
    
    # Summary statistics
    $stats = $mailboxTypes.Values | Group-Object | Sort-Object Name
    Write-Host ""
    Write-Host "Mailbox type retrieval summary:" -ForegroundColor Cyan
    foreach ($stat in $stats) {
        Write-Host "  $($stat.Name): $($stat.Count)" -ForegroundColor Cyan
    }
    Write-Host "Total processed: $($mailboxTypes.Count) users" -ForegroundColor Green
    
    return $mailboxTypes
}

# --------------------------
# Helper: Connect to Graph
# --------------------------
function Connect-GraphIfNeeded {
    $neededScopes = @("Policy.Read.All","Directory.Read.All","RoleManagement.Read.Directory")
    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $context) {
            Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
            Connect-MgGraph -Scopes $neededScopes -ErrorAction Stop | Out-Null
        } else {
            # Ensure we have the required scopes; re-connect if missing
            $currentScopes = $context.Scopes
            $missing = $neededScopes | Where-Object { $currentScopes -notcontains $_ }
            if ($missing.Count -gt 0) {
                Write-Host "Reconnecting to Graph to add missing scopes: $($missing -join ', ')" -ForegroundColor Yellow
                Disconnect-MgGraph -Confirm:$false
                Connect-MgGraph -Scopes $neededScopes -ErrorAction Stop | Out-Null
            }
        }
        Write-Host "Connected to Microsoft Graph successfully." -ForegroundColor Green
        
        # Display connection info
        $context = Get-MgContext
        Write-Host "Tenant: $($context.TenantId)" -ForegroundColor Cyan
        Write-Host "Account: $($context.Account)" -ForegroundColor Cyan
    } catch {
        Write-Error "Failed to connect to Microsoft Graph. $_"
        exit 1
    }
}

# --------------------------
# Helper: Retry wrapper
# --------------------------
function Invoke-WithRetry {
    param(
        [Parameter(Mandatory=$true)][ScriptBlock]$ScriptBlock,
        [string]$Operation = "Graph call",
        [int]$MaxAttempts = 4,
        [int]$BaseDelaySeconds = 3
    )
    $attempt = 0
    do {
        $attempt++
        try {
            return & $ScriptBlock
        } catch {
            $msg = $_.Exception.Message
            $status = $_.Exception.Response.StatusCode.value__ 2>$null
            if ($attempt -lt $MaxAttempts -and ($msg -match 'throttle|429|too many requests|temporar|timeout|503' -or $status -in 429,503)) {
                $delay = [Math]::Min($BaseDelaySeconds * [math]::Pow(2, $attempt-1), 30)
                Write-Warning "Transient error on '$Operation' (attempt $attempt/$MaxAttempts). Sleeping $delay sec. Message: $msg"
                Start-Sleep -Seconds $delay
            } else {
                throw
            }
        }
    } while ($attempt -lt $MaxAttempts)
}

# --------------------------
# Helper: Get all CA policies with enhanced details
# --------------------------
function Get-AllCAPolicies {
    try {
        Write-Host "Attempting to retrieve CA policies..." -ForegroundColor Yellow
        $policies = Invoke-WithRetry -Operation "Get-MgIdentityConditionalAccessPolicy" -ScriptBlock {
            Get-MgIdentityConditionalAccessPolicy -All
        }
        Write-Host "Successfully retrieved $($policies.Count) CA policies" -ForegroundColor Green
        return $policies
    } catch {
        Write-Error "Failed to retrieve Conditional Access policies. Error: $_"
        Write-Host "Please ensure you have the required permissions: Policy.Read.All, Directory.Read.All" -ForegroundColor Yellow
        throw
    }
}

# --------------------------
# Helper: Get users (paged)
# --------------------------
function Get-TenantUsers {
    $filterParts = @()
    switch ($UserTypes) {
        'Member' { $filterParts += "userType eq 'Member'" }
        'Guest'  { $filterParts += "userType eq 'Guest'" }
        'Both'   { } # no filter on userType
    }
    if ($OnlyEnabledUsers) { $filterParts += "accountEnabled eq true" }
    $filter = ($filterParts -join ' and ')
    $props = @('id','displayName','userPrincipalName','userType','accountEnabled','mail','department','jobTitle')
    
    if ([string]::IsNullOrWhiteSpace($filter)) {
        return Invoke-WithRetry -Operation "Get-MgUser (all users)" -ScriptBlock {
            Get-MgUser -All -Property $props
        }
    } else {
        return Invoke-WithRetry -Operation "Get-MgUser (filtered users)" -ScriptBlock {
            Get-MgUser -All -Filter $filter -Property $props
        }
    }
}

# --------------------------
# Helper: Get transitive memberships (groups, roles) for a user
# --------------------------
function Get-UserTransitiveMembership {
    param([Parameter(Mandatory=$true)][string]$UserId)
    
    try {
        $memberOf = Invoke-WithRetry -Operation "Get-MgUserTransitiveMemberOf for $UserId" -ScriptBlock {
            Get-MgUserTransitiveMemberOf -UserId $UserId -All
        }

        # Separate groups and directory roles; use HashSets for O(1) lookups
        $groupSet = [System.Collections.Generic.HashSet[string]]::new()
        $roleSet  = [System.Collections.Generic.HashSet[string]]::new()
        $groupNames = @{}
        $roleNames = @{}

        foreach ($obj in $memberOf) {
            $type = $null
            if ($obj -and $obj.AdditionalProperties -and $obj.AdditionalProperties.ContainsKey('@odata.type')) {
                $type = $obj.AdditionalProperties['@odata.type']
            }
            if ($type -eq '#microsoft.graph.group') {
                if ($obj.Id) { 
                    [void]$groupSet.Add($obj.Id) 
                    $groupNames[$obj.Id] = $obj.DisplayName
                }
            } elseif ($type -eq '#microsoft.graph.directoryRole') {
                if ($obj.Id) { 
                    [void]$roleSet.Add($obj.Id) 
                    $roleNames[$obj.Id] = $obj.DisplayName
                }
            }
        }

        return [PSCustomObject]@{
            GroupIds = $groupSet
            RoleIds  = $roleSet
            GroupNames = $groupNames
            RoleNames = $roleNames
        }
    } catch {
        Write-Warning "Failed to get transitive membership for user $UserId : $_"
        return [PSCustomObject]@{
            GroupIds = [System.Collections.Generic.HashSet[string]]::new()
            RoleIds  = [System.Collections.Generic.HashSet[string]]::new()
            GroupNames = @{}
            RoleNames = @{}
        }
    }
}

# --------------------------
# Helper: Guest/External match evaluator
# --------------------------
function Test-GuestExternalMatch {
    param(
        [Parameter(Mandatory=$true)]$User,
        $GuestExternalCondition # object with State and guestOrExternalUserTypes (optional)
    )
    if (-not $GuestExternalCondition) { return $false }
    if ($GuestExternalCondition.State -ne 'enabled') { return $false }

    # Best-effort: treat Graph userType 'Guest' as guest.
    if ($User.UserType -eq 'Guest') { return $true }

    # More precise sub-type detection would require additional attributes beyond scope here.
    return $false
}

# --------------------------
# Helper: Format policy controls for display
# --------------------------
function Format-PolicyControls {
    param($Policy)
    
    if (-not $Policy.GrantControls -and -not $Policy.SessionControls) {
        return "No controls defined"
    }
    
    $controls = @()
    
    if ($Policy.GrantControls) {
        $grantControls = @()
        if ($Policy.GrantControls.BuiltInControls) {
            $grantControls += $Policy.GrantControls.BuiltInControls
        }
        if ($Policy.GrantControls.CustomAuthenticationFactors) {
            $grantControls += "CustomMFA"
        }
        if ($Policy.GrantControls.TermsOfUse) {
            $grantControls += "TermsOfUse"
        }
        
        $operator = if ($Policy.GrantControls.Operator -eq 'AND') { " AND " } else { " OR " }
        if ($grantControls.Count -gt 0) {
            $controls += "Grant: " + ($grantControls -join $operator)
        }
    }
    
    if ($Policy.SessionControls) {
        $sessionControls = @()
        if ($Policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled) {
            $sessionControls += "AppEnforced"
        }
        if ($Policy.SessionControls.CloudAppSecurity.IsEnabled) {
            $sessionControls += "MCAS"
        }
        if ($Policy.SessionControls.PersistentBrowser.IsEnabled) {
            $sessionControls += "PersistentBrowser"
        }
        if ($Policy.SessionControls.SignInFrequency.IsEnabled) {
            $sessionControls += "SignInFreq"
        }
        
        if ($sessionControls.Count -gt 0) {
            $controls += "Session: " + ($sessionControls -join ", ")
        }
    }
    
    return ($controls -join " | ")
}

# --------------------------
# Helper: Determine if policy targets user
# --------------------------
function Test-PolicyTargetsUser {
    param(
        [Parameter(Mandatory=$true)]$Policy,
        [Parameter(Mandatory=$true)]$User,
        [Parameter(Mandatory=$true)]$UserGroupIdSet,  # HashSet[string]
        [Parameter(Mandatory=$true)]$UserRoleIdSet    # HashSet[string]
    )

    $u = $Policy.Conditions.Users
    if (-not $u) {
        # Likely not a user-scoped policy (e.g., workload identities); skip
        return $false
    }

    $includeUsers  = @($u.IncludeUsers)
    $includeGroups = @($u.IncludeGroups)
    $includeRoles  = @($u.IncludeRoles)

    $excludeUsers  = @($u.ExcludeUsers)
    $excludeGroups = @($u.ExcludeGroups)
    $excludeRoles  = @($u.ExcludeRoles)

    $includeGuests = $null
    $excludeGuests = $null
    if ($u.PSObject.Properties.Name -contains 'IncludeGuestsOrExternalUsers') { $includeGuests = $u.IncludeGuestsOrExternalUsers }
    if ($u.PSObject.Properties.Name -contains 'ExcludeGuestsOrExternalUsers') { $excludeGuests = $u.ExcludeGuestsOrExternalUsers }

    $included = $false
    $includeReason = @()
    
    # Include checks
    if ($includeUsers -contains 'All') {
        $included = $true
        $includeReason += "All Users"
    } else {
        if ($includeUsers -contains $User.Id) {
            $included = $true
            $includeReason += "Direct User"
        }
        if ($includeGroups) {
            $matchingGroups = $includeGroups | Where-Object { $UserGroupIdSet.Contains($_) }
            if ($matchingGroups) {
                $included = $true
                $includeReason += "Group Membership"
            }
        }
        if ($includeRoles) {
            $matchingRoles = $includeRoles | Where-Object { $UserRoleIdSet.Contains($_) }
            if ($matchingRoles) {
                $included = $true
                $includeReason += "Directory Role"
            }
        }
        if (Test-GuestExternalMatch -User $User -GuestExternalCondition $includeGuests) {
            $included = $true
            $includeReason += "Guest/External User"
        }
    }

    if (-not $included) { 
        return @{
            IsTargeted = $false
            Reason = "Not included in policy scope"
        }
    }

    $excludeReason = @()
    # Exclusion checks (take precedence)
    if ($excludeUsers -contains $User.Id) { 
        $excludeReason += "Direct User Exclusion"
    }
    if ($excludeGroups) {
        $matchingExcludeGroups = $excludeGroups | Where-Object { $UserGroupIdSet.Contains($_) }
        if ($matchingExcludeGroups) {
            $excludeReason += "Group Exclusion"
        }
    }
    if ($excludeRoles) {
        $matchingExcludeRoles = $excludeRoles | Where-Object { $UserRoleIdSet.Contains($_) }
        if ($matchingExcludeRoles) {
            $excludeReason += "Role Exclusion"
        }
    }
    if (Test-GuestExternalMatch -User $User -GuestExternalCondition $excludeGuests) { 
        $excludeReason += "Guest/External Exclusion"
    }

    if ($excludeReason.Count -gt 0) {
        return @{
            IsTargeted = $false
            Reason = "Excluded: " + ($excludeReason -join ", ")
        }
    }

    return @{
        IsTargeted = $true
        Reason = "Included: " + ($includeReason -join ", ")
    }
}

# --------------------------
# Main
# --------------------------
$ErrorActionPreference = 'Stop'
Write-Host "Starting Enhanced Conditional Access Policy Coverage Audit..." -ForegroundColor Cyan

# Check mailbox detection method if enabled
if ($CheckMailboxType) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "MAILBOX TYPE DETECTION METHOD" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Choose how to detect mailbox types:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Microsoft Graph API (Recommended)" -ForegroundColor Green
    Write-Host "      - Uses your existing Graph connection" -ForegroundColor Gray
    Write-Host "      - No additional authentication needed" -ForegroundColor Gray
    Write-Host "      - Fast and reliable" -ForegroundColor Gray
    Write-Host "      - Detects: User Mailbox, Shared Mailbox, No Mailbox" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [2] Exchange Online PowerShell" -ForegroundColor Yellow
    Write-Host "      - Requires separate Exchange Online connection" -ForegroundColor Gray
    Write-Host "      - More detailed mailbox type information" -ForegroundColor Gray
    Write-Host "      - May require additional authentication" -ForegroundColor Gray
    Write-Host ""
    
    $choice = Read-Host "Enter your choice (1 or 2) [Default: 1]"
    
    if ([string]::IsNullOrWhiteSpace($choice)) {
        $choice = "1"
    }
    
    if ($choice -eq "1") {
        $script:UseGraphForMailbox = $true
        Write-Host ""
        Write-Host "✓ Using Microsoft Graph API for mailbox detection" -ForegroundColor Green
    } elseif ($choice -eq "2") {
        $script:UseGraphForMailbox = $false
        Write-Host ""
        Write-Host "✓ Using Exchange Online PowerShell for mailbox detection" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "Invalid choice. Defaulting to Microsoft Graph API." -ForegroundColor Yellow
        $script:UseGraphForMailbox = $true
    }
    
    Write-Host ""
}

Ensure-GraphSubmodules
Connect-GraphIfNeeded

# Connect to Exchange Online if mailbox checking is enabled
if ($CheckMailboxType -and -not $script:UseGraphForMailbox) {
    Ensure-ExchangeOnlineModule
    Connect-ExchangeOnlineIfNeeded
}

Write-Host "Retrieving Conditional Access policies..." -ForegroundColor Cyan
$policies = Get-AllCAPolicies
if (-not $policies) {
    Write-Warning "No Conditional Access policies found."
    exit 1
}

# Debug: Show first few policies to understand structure
Write-Host "DEBUG - First policy structure:" -ForegroundColor Magenta
if ($policies.Count -gt 0) {
    $firstPolicy = $policies[0]
    Write-Host "  DisplayName: $($firstPolicy.DisplayName)" -ForegroundColor Magenta
    Write-Host "  State: $($firstPolicy.State)" -ForegroundColor Magenta
    Write-Host "  Id: $($firstPolicy.Id)" -ForegroundColor Magenta
    
    # Show policy states distribution
    $stateGroups = $policies | Group-Object State
    Write-Host "Policy states found:" -ForegroundColor Cyan
    foreach ($group in $stateGroups) {
        Write-Host "  $($group.Name): $($group.Count) policies" -ForegroundColor Cyan
    }
}

Write-Host "Retrieving users (UserTypes: $UserTypes, OnlyEnabledUsers: $OnlyEnabledUsers)..." -ForegroundColor Cyan
$users = Get-TenantUsers

# Apply caller-provided exclusion filter (e.g., service accounts)
$users = $users | Where-Object { -not (& $ExcludeUserFilterScriptBlock $_) }

if (-not $users) {
    Write-Warning "No users matched the selected criteria."
    "" | Out-File -FilePath $OutputPath -Encoding utf8
    return
}

Write-Host "Users found: $($users.Count); Policies found: $($policies.Count)" -ForegroundColor Green

# Get mailbox types in batch if enabled
$mailboxTypeLookup = @{}
if ($CheckMailboxType) {
    $mailboxTypeLookup = Get-MailboxTypesBatch -Users $users
}

# Prepare results
$results = New-Object System.Collections.Generic.List[object]
$matrixRows = if ($EmitMatrix) { New-Object System.Collections.Generic.List[object] } else { $null }
$policyIdToName = @{}
foreach ($p in $policies) { $policyIdToName[$p.Id] = $p.DisplayName }

# Pre-calc policy IDs for matrix columns if needed
$policyIdsOrdered = @($policies | Sort-Object DisplayName | Select-Object -ExpandProperty Id)

# Process each user
$idx = 0
$total = $users.Count
foreach ($user in $users) {
    $idx++
    $progressPercent = [math]::Round(($idx / [math]::Max($total,1)) * 100, 1)
    Write-Progress -Activity "Evaluating CA coverage" -Status "$($user.UserPrincipalName) ($idx of $total)" -PercentComplete $progressPercent

    # Get mailbox type
    $mailboxType = if ($CheckMailboxType -and $mailboxTypeLookup.ContainsKey($user.UserPrincipalName)) {
        $mailboxTypeLookup[$user.UserPrincipalName]
    } else {
        "Not Checked"
    }

    # Resolve transitive memberships (dynamic groups are auto-resolved by Graph)
    $membership = Get-UserTransitiveMembership -UserId $user.Id
    $groupSet = $membership.GroupIds
    $roleSet  = $membership.RoleIds

    # Evaluate policies
    $appliedPolicies = @()
    $policyDetails = @()
    
    foreach ($pol in $policies) {
        $targetResult = Test-PolicyTargetsUser -Policy $pol -User $user -UserGroupIdSet $groupSet -UserRoleIdSet $roleSet
        if ($targetResult.IsTargeted) {
            $appliedPolicies += $pol
            
            # Debug for first user
            if ($idx -eq 1) {
                Write-Host "  Policy '$($pol.DisplayName)' targets user - State: $($pol.State)" -ForegroundColor Magenta
            }
            
            $policyDetail = [PSCustomObject]@{
                PolicyName = $pol.DisplayName
                PolicyId = $pol.Id
                State = $pol.State
                Reason = $targetResult.Reason
                Controls = if ($ShowPolicyDetails) { Format-PolicyControls -Policy $pol } else { "" }
                CreatedDateTime = $pol.CreatedDateTime
                ModifiedDateTime = $pol.ModifiedDateTime
            }
            $policyDetails += $policyDetail
        }
    }

    $enabled    = @($appliedPolicies | Where-Object { $_.State -eq 'enabled' })
    $reportOnly = @($appliedPolicies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' })
    $disabled   = @($appliedPolicies | Where-Object { $_.State -eq 'disabled' })

    # Debug: Log policy information for first few users
    if ($idx -le 3) {
        Write-Host "DEBUG - User: $($user.UserPrincipalName)" -ForegroundColor Magenta
        Write-Host "  Mailbox Type: $mailboxType" -ForegroundColor Magenta
        Write-Host "  Applied policies: $($appliedPolicies.Count)" -ForegroundColor Magenta
        Write-Host "  Enabled policies: $($enabled.Count)" -ForegroundColor Magenta
        if ($enabled.Count -gt 0) {
            foreach ($ep in $enabled) {
                Write-Host "    - $($ep.DisplayName) | State: $($ep.State)" -ForegroundColor Magenta
            }
        }
    }

    # Enhanced policy formatting with better error handling
    function Format-PolicyForDisplay {
        param($Policy)
        
        if (-not $Policy) { return "Unknown Policy" }
        
        $displayName = if ($Policy.DisplayName) { $Policy.DisplayName } else { "Unnamed Policy" }
        $state = if ($Policy.State) { $Policy.State } else { "Unknown State" }
        
        $controls = ""
        if ($ShowPolicyDetails) {
            $controls = " [Controls: $(Format-PolicyControls -Policy $Policy)]"
        }
        
        return "$displayName (State: $state)$controls"
    }

    # Classify account type based on mailbox type
    $accountType = switch ($mailboxType) {
        "UserMailbox" { "User" }
        "SharedMailbox" { "Shared Mailbox" }
        "RoomMailbox" { "Room Mailbox" }
        "EquipmentMailbox" { "Equipment Mailbox" }
        "No Mailbox" { "No Mailbox" }
        "Not Checked" { "Not Checked" }
        "Error" { "Error" }
        default { $mailboxType }
    }

    $result = [PSCustomObject]@{
        UserPrincipalName             = $user.UserPrincipalName
        DisplayName                   = $user.DisplayName
        UserId                        = $user.Id
        UserType                      = $user.UserType
        AccountEnabled                = $user.AccountEnabled
        AccountType                   = $accountType
        MailboxType                   = $mailboxType
        Mail                          = if ($user.Mail) { $user.Mail } else { "" }
        Department                    = if ($user.Department) { $user.Department } else { "" }
        JobTitle                      = if ($user.JobTitle) { $user.JobTitle } else { "" }
        
        GroupMembershipCount          = $groupSet.Count
        RoleMembershipCount           = $roleSet.Count
        GroupNames                    = if ($membership.GroupNames.Values) { (($membership.GroupNames.Values | Sort-Object) -join '; ') } else { "" }
        RoleNames                     = if ($membership.RoleNames.Values) { (($membership.RoleNames.Values | Sort-Object) -join '; ') } else { "" }

        AppliedPolicyCount_All        = $appliedPolicies.Count
        AppliedPolicyCount_Enabled    = $enabled.Count
        AppliedPolicyCount_ReportOnly = $reportOnly.Count
        AppliedPolicyCount_Disabled   = $disabled.Count

        # Enhanced policy lists with better formatting and error handling
        EnforcedPolicies              = if ($enabled.Count -gt 0) { 
            ($enabled | ForEach-Object { Format-PolicyForDisplay -Policy $_ }) -join ' | ' 
        } else { 
            "No enforced policies" 
        }
        ReportOnlyPolicies            = if ($reportOnly.Count -gt 0) { 
            ($reportOnly | ForEach-Object { Format-PolicyForDisplay -Policy $_ }) -join ' | ' 
        } else { 
            "No report-only policies" 
        }
        DisabledPolicies              = if ($disabled.Count -gt 0) { 
            ($disabled | ForEach-Object { Format-PolicyForDisplay -Policy $_ }) -join ' | ' 
        } else { 
            "No disabled policies" 
        }
        AllAppliedPolicies            = if ($appliedPolicies.Count -gt 0) { 
            ($appliedPolicies | ForEach-Object { Format-PolicyForDisplay -Policy $_ }) -join ' | ' 
        } else { 
            "No policies applied" 
        }

        # Status flags
        HasAnyPolicyApplied           = $appliedPolicies.Count -gt 0
        HasEnforcedPolicy             = $enabled.Count -gt 0
        IsProtectedByCA               = $enabled.Count -gt 0
        
        # Risk assessment
        RiskLevel                     = if ($enabled.Count -eq 0) { "HIGH - No enforced policies" } 
                                       elseif ($enabled.Count -lt 3) { "MEDIUM - Limited policy coverage" } 
                                       else { "LOW - Good policy coverage" }
    }
    $results.Add($result)

    if ($EmitMatrix) {
        # Build a wide row: one column per policy, value indicates state (E=Enabled, R=Report-only, D=Disabled, 0=Not Applied)
        $row = [ordered]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName       = $user.DisplayName
            UserId            = $user.Id
            UserType          = $user.UserType
            AccountType       = $accountType
            MailboxType       = $mailboxType
        }
        $appliedPolicyStates = @{}
        foreach ($p in $appliedPolicies) { 
            $appliedPolicyStates[$p.Id] = switch ($p.State) {
                'enabled' { 'E' }
                'enabledForReportingButNotEnforced' { 'R' }
                'disabled' { 'D' }
                default { '?' }
            }
        }
        foreach ($PolicyId in $policyIdsOrdered) {
            $row[$policyIdToName[$PolicyId]] = if ($appliedPolicyStates.ContainsKey($PolicyId)) { $appliedPolicyStates[$PolicyId] } else { '0' }
        }
        $matrixRows.Add([PSCustomObject]$row)
    }
}

Write-Progress -Activity "Evaluating CA coverage" -Completed

# Export CSV
Write-Host "Writing enhanced coverage CSV: $OutputPath" -ForegroundColor Cyan
$results | Sort-Object UserPrincipalName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

if ($EmitMatrix) {
    $matrixPath = [System.IO.Path]::ChangeExtension($OutputPath, $null) + "_MATRIX.csv"
    Write-Host "Writing matrix CSV: $matrixPath" -ForegroundColor Cyan
    Write-Host "Matrix legend: E=Enabled, R=Report-only, D=Disabled, 0=Not Applied" -ForegroundColor Yellow
    $matrixRows | Export-Csv -Path $matrixPath -NoTypeInformation -Encoding UTF8
}

# Enhanced Summary
$notCoveredAll = @($results | Where-Object { -not $_.HasAnyPolicyApplied })
$notCoveredEnabled = @($results | Where-Object { -not $_.HasEnforcedPolicy })
$highRiskUsers = @($results | Where-Object { $_.RiskLevel -like "HIGH*" })
$mediumRiskUsers = @($results | Where-Object { $_.RiskLevel -like "MEDIUM*" })

# Mailbox type statistics
if ($CheckMailboxType) {
    $mailboxStats = $results | Group-Object AccountType | Sort-Object Name
    $sharedMailboxes = @($results | Where-Object { $_.AccountType -eq "Shared Mailbox" })
}

Write-Host ""
Write-Host "========== ENHANCED SUMMARY ==========" -ForegroundColor Green
Write-Host ("Total Users Evaluated:           {0}" -f $results.Count)
Write-Host ("Users with NO policies:          {0}" -f $notCoveredAll.Count) -ForegroundColor $(if ($notCoveredAll.Count -gt 0) { "Red" } else { "Green" })
Write-Host ("Users with NO enforced policies: {0}" -f $notCoveredEnabled.Count) -ForegroundColor $(if ($notCoveredEnabled.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host ("High Risk Users:                 {0}" -f $highRiskUsers.Count) -ForegroundColor $(if ($highRiskUsers.Count -gt 0) { "Red" } else { "Green" })
Write-Host ("Medium Risk Users:               {0}" -f $mediumRiskUsers.Count) -ForegroundColor $(if ($mediumRiskUsers.Count -gt 0) { "Yellow" } else { "Green" })

if ($CheckMailboxType) {
    Write-Host ""
    Write-Host "ACCOUNT TYPE DISTRIBUTION:" -ForegroundColor Cyan
    foreach ($stat in $mailboxStats) {
        $color = switch ($stat.Name) {
            'Shared Mailbox' { 'Yellow' }
            'User' { 'Green' }
            'Room Mailbox' { 'Cyan' }
            'Equipment Mailbox' { 'Cyan' }
            'No Mailbox' { 'Gray' }
            default { 'White' }
        }
        Write-Host ("  {0}: {1}" -f $stat.Name, $stat.Count) -ForegroundColor $color
    }
    
    if ($sharedMailboxes.Count -gt 0) {
        Write-Host ""
        Write-Host "SHARED MAILBOXES:" -ForegroundColor Yellow
        $sharedMailboxes | Select-Object -First 10 | ForEach-Object {
            $policyStatus = if ($_.HasEnforcedPolicy) { "Protected" } else { "NOT Protected" }
            $color = if ($_.HasEnforcedPolicy) { "Green" } else { "Red" }
            Write-Host ("  - {0} ({1}) - {2}" -f $_.UserPrincipalName, $_.DisplayName, $policyStatus) -ForegroundColor $color
        }
        if ($sharedMailboxes.Count -gt 10) {
            Write-Host "  ... and $($sharedMailboxes.Count - 10) more" -ForegroundColor Yellow
        }
    }
}

if ($highRiskUsers.Count -gt 0) {
    Write-Host ""
    Write-Host "HIGH RISK USERS (No enforced CA policies):" -ForegroundColor Red
    $highRiskUsers | Select-Object -First 10 | ForEach-Object { 
        $accountInfo = if ($CheckMailboxType) { " [$($_.AccountType)]" } else { "" }
        Write-Host "  - $($_.UserPrincipalName) ($($_.DisplayName))$accountInfo" -ForegroundColor Red 
    }
    if ($highRiskUsers.Count -gt 10) {
        Write-Host "  ... and $($highRiskUsers.Count - 10) more" -ForegroundColor Red
    }
}

if ($mediumRiskUsers.Count -gt 0) {
    Write-Host ""
    Write-Host "MEDIUM RISK USERS (Limited CA policy coverage):" -ForegroundColor Yellow
    $mediumRiskUsers | Select-Object -First 5 | ForEach-Object { 
        $accountInfo = if ($CheckMailboxType) { " [$($_.AccountType)]" } else { "" }
        Write-Host "  - $($_.UserPrincipalName) ($($_.DisplayName))$accountInfo - $($_.AppliedPolicyCount_Enabled) enforced policies" -ForegroundColor Yellow 
    }
}

# Policy Statistics
$policyStats = $policies | Group-Object State | Sort-Object Name
Write-Host ""
Write-Host "CONDITIONAL ACCESS POLICY STATISTICS:" -ForegroundColor Cyan
foreach ($stat in $policyStats) {
    $color = switch ($stat.Name) {
        'enabled' { 'Green' }
        'enabledForReportingButNotEnforced' { 'Yellow' }
        'disabled' { 'Gray' }
        default { 'White' }
    }
    Write-Host ("  {0}: {1} policies" -f $stat.Name, $stat.Count) -ForegroundColor $color
}

Write-Host ""
Write-Host "Output files created:" -ForegroundColor Green
Write-Host "  Main Report: $OutputPath" -ForegroundColor Green
if ($EmitMatrix) {
    Write-Host "  Matrix Report: $([System.IO.Path]::ChangeExtension($OutputPath, $null))_MATRIX.csv" -ForegroundColor Green
}

Write-Host "=====================================" -ForegroundColor Green
Write-Host "Enhanced CA Policy Coverage Audit Complete!" -ForegroundColor Green

# Cleanup Exchange Online connection if we connected
if ($CheckMailboxType -and -not $script:UseGraphForMailbox) {
    try {
        $existingSession = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if ($existingSession) {
            Write-Host ""
            Write-Host "Disconnecting from Exchange Online..." -ForegroundColor Cyan
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "Disconnected from Exchange Online." -ForegroundColor Green
        }
    } catch {
        # Silently ignore cleanup errors
    }
}
