<#
.SYNOPSIS
    Exports Microsoft 365 sign-in logs for specified users.

.DESCRIPTION
    This script retrieves interactive and non-interactive sign-in logs from Microsoft Graph API
    for specified users within a given date range. It supports relative date periods and custom
    date ranges with automatic validation.

.PARAMETER UserUPNs
    Comma-separated list of user UPNs to export sign-in data for.

.PARAMETER StartDate
    Start date for the export in YYYY-MM-DD format. Maximum range is 1 month.

.PARAMETER EndDate
    End date for the export in YYYY-MM-DD format.

.PARAMETER RelativePeriod
    Relative time period: "lastday", "last3days", "lastweek", "lastmonth"

.PARAMETER ExportPath
    Custom export directory path. Defaults to "exports" in current directory.

.PARAMETER MaxRetries
    Maximum number of retry attempts for API calls. Default is 3.

.PARAMETER MaxConcurrentJobs
    Maximum number of users to process simultaneously. Range: 1-20, Default is 5.
    Higher values = faster processing but more system resources.

.EXAMPLE
    .\signins.ps1 -UserUPNs "user1@example.com,user2@example.com" -RelativePeriod "lastweek"

.EXAMPLE
    .\signins.ps1 -UserUPNs "user@example.com" -StartDate "2024-01-01" -EndDate "2024-01-31"

.EXAMPLE
    .\signins.ps1 -UserUPNs "user1@example.com,user2@example.com" -RelativePeriod "lastweek" -MaxConcurrentJobs 10

.NOTES
    Requires Microsoft.Graph PowerShell module and appropriate permissions (AuditLog.Read.All).
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string[]]$UserUPNs,

    [Parameter()]
    [string]$StartDate,

    [Parameter()]
    [string]$EndDate,

    [Parameter()]
    [ValidateSet("lastday", "last3days", "lastweek", "lastmonth", IgnoreCase = $true)]
    [string]$RelativePeriod,

    [Parameter()]
    [string]$ExportPath,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$MaxRetries,

    [Parameter()]
    [ValidateRange(1, 20)]
    [int]$MaxConcurrentJobs
)

# ----- Load Configuration -----
function Get-Config {
    $configPath = "signins_config.json"

    # Define default configuration structure
    $defaultConfig = @{
        directories = @{
            exports_dir = "exports"
        }
        performance = @{
            max_retries = 3
            max_concurrent_jobs = 5
        }
        logging = @{
            level = "Info"
            colors_enabled = $true
        }
    }

    if (Test-Path $configPath) {
        try {
            $config = Get-Content $configPath | ConvertFrom-Json

            # Validate and merge with defaults to ensure all required fields exist
            if (-not $config.directories) {
                $config | Add-Member -NotePropertyName "directories" -NotePropertyValue $defaultConfig.directories
            }
            if (-not $config.directories.exports_dir) {
                $config.directories | Add-Member -NotePropertyName "exports_dir" -NotePropertyValue $defaultConfig.directories.exports_dir
            }

            if (-not $config.performance) {
                $config | Add-Member -NotePropertyName "performance" -NotePropertyValue $defaultConfig.performance
            }
            if (-not $config.performance.max_retries) {
                $config.performance | Add-Member -NotePropertyName "max_retries" -NotePropertyValue $defaultConfig.performance.max_retries
            }
            if (-not $config.performance.max_concurrent_jobs) {
                $config.performance | Add-Member -NotePropertyName "max_concurrent_jobs" -NotePropertyValue $defaultConfig.performance.max_concurrent_jobs
            }

            # Validate and ensure logging configuration
            $loggingWarnings = @()
            if (-not $config.logging) {
                $config | Add-Member -NotePropertyName "logging" -NotePropertyValue $defaultConfig.logging
                $loggingWarnings += "Missing 'logging' section in config file. Using defaults."
            } else {
                # Validate logging level
                $validLevels = @("Error", "Warning", "Info", "Success", "Debug")
                if (-not $config.logging.level -or $config.logging.level -notin $validLevels) {
                    $config.logging.level = $defaultConfig.logging.level
                    $loggingWarnings += "Invalid or missing 'logging.level' in config file. Using default: $($defaultConfig.logging.level)"
                }

                # Validate colors_enabled (ensure it's boolean)
                if ($config.logging.PSObject.Properties.Name -notcontains "colors_enabled" -or $config.logging.colors_enabled -isnot [bool]) {
                    $config.logging.colors_enabled = $defaultConfig.logging.colors_enabled
                    $loggingWarnings += "Invalid or missing 'logging.colors_enabled' in config file. Using default: $($defaultConfig.logging.colors_enabled)"
                }
            }

            # Store warnings to be logged after Write-Log is available
            $config | Add-Member -NotePropertyName "_configWarnings" -NotePropertyValue $loggingWarnings -Force

            return $config
        }
        catch {
            # Use Write-Warning to avoid circular dependency during config loading
            Write-Warning "Error loading config file $configPath : $($_.Exception.Message)"
            Write-Warning "Using hardcoded defaults."
        }
    }
    else {
        # Use Write-Warning to avoid circular dependency during config loading
        Write-Warning "Config file $configPath not found. Using hardcoded defaults."
    }

    # Return complete default configuration if config file is missing or invalid
    return $defaultConfig
}

# Universal logging function for both main script and runspace contexts
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success", "Debug")]
        [string]$Level = "Info",
        [switch]$CaptureOutput,    # For runspace message collection
        [switch]$NoConsole        # For runspace console suppression
    )

    # Get logging configuration (guaranteed to exist after Get-Config, but handle initial loading)
    if ($script:config -and $script:config.logging) {
        $logConfig = $script:config.logging
        $minLogLevel = $logConfig.level
        $colorsEnabled = $logConfig.colors_enabled
    } else {
        # Fallback defaults during initial config loading
        $minLogLevel = "Info"
        $colorsEnabled = $true
    }

    # Define log level hierarchy for filtering
    $levelHierarchy = @{
        "Error" = 0
        "Warning" = 1
        "Info" = 2
        "Success" = 2
        "Debug" = 3
    }

    # Check if this message should be logged based on configured level
    $currentLevelValue = if ($levelHierarchy.ContainsKey($Level)) { $levelHierarchy[$Level] } else { 2 }
    $minLevelValue = if ($levelHierarchy.ContainsKey($minLogLevel)) { $levelHierarchy[$minLogLevel] } else { 2 }

    if ($currentLevelValue -gt $minLevelValue) {
        return  # Skip logging if level is below configured minimum
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Capture output for runspace collection if requested
    if ($CaptureOutput) {
        # Initialize the array if it doesn't exist (for runspace context)
        if (-not $script:outputMessages) {
            $script:outputMessages = @()
        }
        $script:outputMessages += $logMessage
    }

    # Console output (unless suppressed)
    if (-not $NoConsole) {
        if ($colorsEnabled) {
            switch ($Level) {
                "Info"    {
                    $Host.UI.WriteLine([System.ConsoleColor]::Gray, $Host.UI.RawUI.BackgroundColor, $logMessage)
                }
                "Warning" {
                    $Host.UI.WriteLine([System.ConsoleColor]::Yellow, $Host.UI.RawUI.BackgroundColor, $logMessage)
                }
                "Error"   {
                    $Host.UI.WriteLine([System.ConsoleColor]::Red, $Host.UI.RawUI.BackgroundColor, $logMessage)
                }
                "Success" {
                    $Host.UI.WriteLine([System.ConsoleColor]::Green, $Host.UI.RawUI.BackgroundColor, $logMessage)
                }
                "Debug"   {
                    $Host.UI.WriteLine([System.ConsoleColor]::Cyan, $Host.UI.RawUI.BackgroundColor, $logMessage)
                }
            }
        } else {
            Write-Output $logMessage
        }
    }
}

# UPN validation
function Confirm-UPN {
    param (
        [string]$UPN
    )

    if ([string]::IsNullOrWhiteSpace($UPN)) {
        Write-Log "Empty UPN provided" -Level Error
        return $false
    }

    $upnPattern = '^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$'

    if ($UPN -notmatch $upnPattern) {
        Write-Log "Invalid UPN format: '$UPN'" -Level Error
        return $false
    }

    if ($UPN.Length -gt 320) {  # RFC 5321 limit
        Write-Log "UPN too long (max 320 characters): '$UPN'" -Level Error
        return $false
    }

    return $true
}

# Function to calculate date range based on relative period
function Get-DateRangeFromRelativePeriod {
    param (
        [string]$RelativePeriod
    )

    $currentDate = Get-Date
    $startDate = $null
    $endDate = $currentDate.ToString("yyyy-MM-ddT23:59:59Z")

    # Calculate the maximum allowed start date (1 month ago)
    $maxStartDate = $currentDate.AddMonths(-1).ToString("yyyy-MM-ddT00:00:00Z")

    switch ($RelativePeriod.ToLower()) {
        "lastday" {
            $startDate = $currentDate.AddDays(-1).ToString("yyyy-MM-ddT00:00:00Z")
        }
        "last3days" {
            $startDate = $currentDate.AddDays(-3).ToString("yyyy-MM-ddT00:00:00Z")
        }
        "lastweek" {
            $startDate = $currentDate.AddDays(-7).ToString("yyyy-MM-ddT00:00:00Z")
        }
        "lastmonth" {
            $startDate = $maxStartDate
        }
        default {
            Write-Log "Invalid relative period specified. Using default of last month." -Level Warning
            $startDate = $maxStartDate
        }
    }

    return @{
        StartDate = $startDate
        EndDate = $endDate
    }
}

# Function to validate date format
function Test-DateFormat {
    param (
        [string]$DateString
    )

    try {
        [datetime]::ParseExact($DateString, "yyyy-MM-dd", $null)
        return $true
    } catch {
        return $false
    }
}

# Function to validate and adjust date range (max 1 month)
function Test-DateRange {
    param (
        [ref]$StartDate,
        [ref]$EndDate
    )

    $currentDate = Get-Date
    $maxStartDate = $currentDate.AddMonths(-1)

    try {
        $startDateTime = [datetime]::ParseExact($StartDate.Value, "yyyy-MM-dd", $null)
        $endDateTime = [datetime]::ParseExact($EndDate.Value, "yyyy-MM-dd", $null)

        if ($startDateTime -gt $endDateTime) {
            Write-Log "Error: Start date must be before end date." -Level Error
            return $false
        }

        if ($startDateTime -lt $maxStartDate) {
            Write-Log "Warning: Maximum allowed period is 1 month. Adjusting date range to last month." -Level Warning
            $StartDate.Value = $maxStartDate.ToString("yyyy-MM-dd")
            $EndDate.Value = (Get-Date).ToString("yyyy-MM-dd")
        }

        return $true
    } catch {
        Write-Log "Error: Invalid date format. Please use YYYY-MM-DD format." -Level Error
        return $false
    }
}

# If no UPNs are provided, ask the user for input
if (-not $UserUPNs) {
    $UserUPNs = (Read-Host "Enter the UPNs of users (comma-separated, e.g., user1@example.com,user2@example.com)").Split(",")
}

# Validate input
if (-not $UserUPNs -or $UserUPNs.Trim() -eq '') {
    Write-Log "No UPNs provided. Exiting script." -Level Error
    exit 1
}

# Convert input into an array
$UserUPNArray = $UserUPNs -split '[, ]+' | ForEach-Object { $_.Trim() }

# Validate each UPN format
$validUPNs = @()
$hasErrors = $false

foreach ($UserUPN in $UserUPNArray) {
    if (Confirm-UPN -UPN $UserUPN) {
        $validUPNs += $UserUPN
    } else {
        $hasErrors = $true
    }
}

# Exit if any UPN validation failed
if ($hasErrors -or $validUPNs.Count -eq 0) {
    Write-Log "One or more UPNs are invalid. Please correct the UPN format and try again." -Level Error
    exit 1
}

# Update the array to only include valid UPNs
$UserUPNArray = $validUPNs

# Define date range (last month)
$LastMonthStart = (Get-Date).AddMonths(-1).ToString("yyyy-MM-ddT00:00:00Z")
$Today = (Get-Date).ToString("yyyy-MM-ddT23:59:59Z")

if ($RelativePeriod) {
    $dateRange = Get-DateRangeFromRelativePeriod -RelativePeriod $RelativePeriod
    $LastMonthStart = $dateRange.StartDate
    $Today = $dateRange.EndDate
    Write-Log "Using relative date range: $RelativePeriod" -Level Info
} elseif ($StartDate -and $EndDate) {
    $startDateValid = Test-DateFormat -DateString $StartDate
    $endDateValid = Test-DateFormat -DateString $EndDate

    if (-not $startDateValid -or -not $endDateValid) {
        Write-Log "Invalid date format in parameters. Please use YYYY-MM-DD format." -Level Error
        exit 1
    }

    if (-not (Test-DateRange -StartDate ([ref]$StartDate) -EndDate ([ref]$EndDate))) {
        Write-Log "Script execution stopped due to invalid date range in parameters." -Level Error
        exit 1
    }

    $LastMonthStart = "$StartDate" + "T00:00:00Z"
    $Today = "$EndDate" + "T23:59:59Z"
    Write-Log "Using custom date range: $StartDate to $EndDate" -Level Info
} else {
    # Prompt for date range if not provided
    do {
        $dateOption = Read-Host "Choose date range option (1=Relative, 2=Custom, 3=Default Last Month, q=Quit the script)"
        $continueMainLoop = $true

        switch ($dateOption) {
            "1" {
                do {
                    $relativeChoice = Read-Host "Choose relative period: 1=Last Day, 2=Last 3 Days, 3=Last Week, 4=Last Month, b=Back"
                    $continueRelativeLoop = $true

                    if ($relativeChoice -eq "b") {
                        $continueRelativeLoop = $false
                        $continueMainLoop = $true
                    } elseif ($relativeChoice -match '^[1-4]$') {
                        $relativeOptions = @("lastday", "last3days", "lastweek", "lastmonth")
                        $RelativePeriod = $relativeOptions[$relativeChoice - 1]
                        $dateRange = Get-DateRangeFromRelativePeriod -RelativePeriod $RelativePeriod
                        $LastMonthStart = $dateRange.StartDate
                        $Today = $dateRange.EndDate
                        Write-Log "Using relative date range: $RelativePeriod" -Level Info
                        $continueRelativeLoop = $false
                        $continueMainLoop = $false
                    } else {
                        Write-Log "Invalid choice. Please try again." -Level Warning
                    }
                } while ($continueRelativeLoop)
            }
            "2" {
                do {
                    $StartDate = Read-Host "Enter start date (YYYY-MM-DD) or 'b' to go back"
                    if ($StartDate -eq "b") {
                        break
                    }

                    $EndDate = Read-Host "Enter end date (YYYY-MM-DD) or 'b' to go back"
                    if ($EndDate -eq "b") {
                        break
                    }

                    $startDateValid = Test-DateFormat -DateString $StartDate
                    $endDateValid = Test-DateFormat -DateString $EndDate

                    if (-not $startDateValid -or -not $endDateValid) {
                        Write-Log "Invalid date format. Please use YYYY-MM-DD format." -Level Error
                        continue
                    }

                    if (-not (Test-DateRange -StartDate ([ref]$StartDate) -EndDate ([ref]$EndDate))) {
                        Write-Log "Invalid date range. Please try again." -Level Error
                        continue
                    }

                    $LastMonthStart = "$StartDate" + "T00:00:00Z"
                    $Today = "$EndDate" + "T23:59:59Z"
                    Write-Log "Using custom date range: $StartDate to $EndDate" -Level Info
                    $continueMainLoop = $false
                    break
                } while ($true)
            }
            "3" {
                Write-Log "Using default date range: Last month" -Level Info
                $continueMainLoop = $false
            }
            "q" {
                Write-Log "Exiting script." -Level Info
                exit 0
            }
            default {
                Write-Log "Invalid option. Please try again." -Level Warning
            }
        }
    } while ($continueMainLoop)
}

# ----- Load Configuration and Apply Defaults -----
$script:config = Get-Config

# Process any configuration warnings that were stored during loading
if ($script:config._configWarnings -and $script:config._configWarnings.Count -gt 0) {
    foreach ($warning in $script:config._configWarnings) {
        Write-Log $warning -Level Warning
    }
    # Remove the temporary warnings property
    $script:config.PSObject.Properties.Remove('_configWarnings')
}

Write-Log "Configuration loaded successfully" -Level Info

# Update parameters with config values if they weren't explicitly provided
if ([string]::IsNullOrEmpty($ExportPath)) {
    $ExportPath = $script:config.directories.exports_dir
}
# Always resolve ExportPath relative to the script's directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ExportPath = Join-Path $ScriptDir $ExportPath
if ($MaxRetries -eq 0) {
    $MaxRetries = $script:config.performance.max_retries
}
if ($MaxConcurrentJobs -eq 0) {
    $MaxConcurrentJobs = $script:config.performance.max_concurrent_jobs
}

Write-Log "Using configuration: ExportPath='$ExportPath', MaxRetries=$MaxRetries, MaxConcurrentJobs=$MaxConcurrentJobs, LogLevel='$($script:config.logging.level)', ColorsEnabled=$($script:config.logging.colors_enabled)" -Level Info

# Ensure Export directory exists
if (!(Test-Path $ExportPath)) {
    try {
        New-Item -ItemType Directory -Path $ExportPath | Out-Null
    } catch {
        Write-Log "Failed to create export directory. Exiting script." -Level Error
        exit 1
    }
}

# Authenticate with Microsoft Graph (No Import-Module needed)
try {
    Connect-MgGraph -Scopes "AuditLog.Read.All" -NoWelcome
} catch {
    Write-Log "Failed to authenticate with Microsoft Graph. Exiting script." -Level Error
    exit 1
}

# Process each UPN
Write-Log "Starting sign-in data export process" -Level Info
Write-Log "Processing $($UserUPNArray.Count) user(s) in parallel (Max concurrent: $MaxConcurrentJobs)" -Level Info

$exportResults = @()
$processedCount = 0
$successfulCount = 0
$failedCount = 0

# Create runspace pool for parallel processing with shared functions
$InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

# Add the Write-Log function to the initial session state
$WriteLogFunction = Get-Command Write-Log
$InitialSessionState.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry('Write-Log', $WriteLogFunction.Definition)))

$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrentJobs, $InitialSessionState, $Host)
$RunspacePool.Open()

# Create script block for parallel execution
$ScriptBlock = {
    param($UserUPN, $LastMonthStart, $Today, $ExportPath, $MaxRetries)

    # Capture output for return
    $script:outputMessages = @()

    function Invoke-GraphRequestWithRetry {
        param (
            [string]$Uri,
            [string]$Method = "GET",
            [hashtable]$Headers = @{},
            [int]$MaxRetries = 3,
            [string]$UserUPN = "Unknown"
        )

        $attempt = 1

        while ($attempt -le $MaxRetries) {
            try {
                if ($attempt -gt 1) {
                    Write-Log -CaptureOutput -NoConsole "[$UserUPN] API retry attempt $attempt/$MaxRetries" -Level Warning
                }

                $response = Invoke-MgGraphRequest -OutputType json -Uri $Uri -Method $Method -Headers $Headers
                return $response

            } catch {
                $errorMessage = $_.Exception.Message
                Write-Log -CaptureOutput -NoConsole "[$UserUPN] API call failed on attempt $attempt`: $errorMessage" -Level Warning

                if ($attempt -eq $MaxRetries) {
                    Write-Log -CaptureOutput -NoConsole "[$UserUPN] All API retry attempts exhausted" -Level Error
                    throw "Failed to complete API request after $MaxRetries attempts. Last error: $errorMessage"
                }

                # Exponential backoff
                $waitTime = [Math]::Pow(2, $attempt) * 2
                Write-Log -CaptureOutput -NoConsole "[$UserUPN] Waiting $waitTime seconds before retry..." -Level Info
                Start-Sleep -Seconds $waitTime

                $attempt++
            }
        }
    }

    function Export-SignIn {
        param (
            [string]$Uri,
            [string]$CSVPath,
            [hashtable]$Headers,
            [string]$SignInType = "Unknown",
            [int]$MaxRetries = 3,
            [string]$UserUPN = "Unknown"
        )

        try {
            Write-Log -CaptureOutput -NoConsole "[$UserUPN] Starting ${SignInType} sign-ins export..." -Level Info

            $allData = @()
            $currentUri = $Uri
            $pageCount = 0
            $totalRecords = 0
            $estimatedTotalPages = $null

            # First call to get count estimation
            $response = Invoke-GraphRequestWithRetry -Uri $currentUri -Headers $Headers -MaxRetries $MaxRetries -UserUPN $UserUPN
            $data = $response | ConvertFrom-Json

            if ($data.value -and $data.value.Count -gt 0) {
                $pageCount = 1
                $currentPageSize = $data.value.Count
                $allData += $data.value
                $totalRecords += $currentPageSize

                # Try to estimate total pages based on @odata.count if available
                if ($data.'@odata.count') {
                    $estimatedTotalRecords = $data.'@odata.count'
                    $estimatedTotalPages = [math]::Ceiling($estimatedTotalRecords / $currentPageSize)
                    Write-Log -CaptureOutput -NoConsole "[$UserUPN] ${SignInType}: Found ~$estimatedTotalRecords records, estimated $estimatedTotalPages pages" -Level Info
                } else {
                    Write-Log -CaptureOutput -NoConsole "[$UserUPN] ${SignInType}: Page 1 processed ($currentPageSize records)" -Level Info
                }

                $currentUri = $data.'@odata.nextLink'

                # Continue with remaining pages
                while ($currentUri) {
                    $pageCount++
                    $response = Invoke-GraphRequestWithRetry -Uri $currentUri -Headers $Headers -MaxRetries $MaxRetries -UserUPN $UserUPN
                    $data = $response | ConvertFrom-Json

                    if ($data.value -and $data.value.Count -gt 0) {
                        $allData += $data.value
                        $totalRecords += $data.value.Count

                        # Show progress with percentage if we have estimated total
                        if ($estimatedTotalPages) {
                            $progressPercent = [math]::Round(($pageCount / $estimatedTotalPages) * 100, 1)
                            Write-Log -CaptureOutput -NoConsole "[$UserUPN] ${SignInType}: Page $pageCount/$estimatedTotalPages ($progressPercent%) - $($data.value.Count) records" -Level Info
                        } else {
                            Write-Log -CaptureOutput -NoConsole "[$UserUPN] ${SignInType}: Page $pageCount processed ($($data.value.Count) records)" -Level Info
                        }
                    }

                    $currentUri = $data.'@odata.nextLink'
                }
            }

            if ($allData.Count -gt 0) {
                Write-Log -CaptureOutput -NoConsole "[$UserUPN] ${SignInType}: Processing $totalRecords records for export..." -Level Info
                $processedData = $allData | Select-Object `
                    @{Name="Date (UTC)"; Expression={$_.createdDateTime}},
                    @{Name="Request ID"; Expression={$_.id}},
                    @{Name="User agent"; Expression={$_.userAgent}},
                    @{Name="Correlation ID"; Expression={$_.correlationId}},
                    @{Name="User ID"; Expression={$_.userId}},
                    @{Name="User"; Expression={$_.userDisplayName}},
                    @{Name="Username"; Expression={$_.userPrincipalName}},
                    @{Name="User type"; Expression={$_.userType}},
                    @{Name="Cross tenant access type"; Expression={$_.crossTenantAccessType}},
                    @{Name="Authentication Protocol"; Expression={$_.authenticationProtocol}},
                    @{Name="Unique token identifier"; Expression={$_.uniqueTokenIdentifier}},
                    @{Name="Original transfer method"; Expression={$_.originalTransferMethod}},
                    @{Name="Client credential type"; Expression={$_.clientCredentialType}},
                    @{Name="Token Protection - Sign In Session"; Expression={$_.tokenProtectionStatusDetails.signInSessionStatus}},
                    @{Name="Token Protection - Sign In Session StatusCode"; Expression={$_.tokenProtectionStatusDetails.signInSessionStatusCode}},
                    @{Name="Application"; Expression={$_.appDisplayName}},
                    @{Name="Application ID"; Expression={$_.appId}},
                    @{Name="App owner tenant ID"; Expression={$_.appOwnerTenantId}},
                    @{Name="Resource"; Expression={$_.resourceDisplayName}},
                    @{Name="Resource ID"; Expression={$_.resourceId}},
                    @{Name="Resource tenant ID"; Expression={$_.resourceTenantId}},
                    @{Name="Resource owner tenant ID"; Expression={$_.resourceOwnerTenantId}},
                    @{Name="Home tenant ID"; Expression={$_.homeTenantId}},
                    @{Name="Home tenant name"; Expression={$_.homeTenantName}},
                    @{Name="IP address"; Expression={$_.ipAddress}},
                    @{Name="Location"; Expression={
                        if ($_.location.city -or $_.location.state -or $_.location.countryOrRegion) {
                            "$($_.location.city), $($_.location.state), $($_.location.countryOrRegion)".Trim(', ')
                        } else { "Unknown" }
                    }},
                    @{Name="Status"; Expression={
                        if ($_.status.errorCode -eq 0) { "Success" }
                        elseif ($_.status.errorCode) { "Interrupted" }
                        else { "Unknown" }
                    }},
                    @{Name="Sign-in error code"; Expression={$_.status.errorCode}},
                    @{Name="Failure reason"; Expression={$_.status.failureReason}},
                    @{Name="Client app"; Expression={$_.clientAppUsed}},
                    @{Name="Device ID"; Expression={$_.deviceDetail.deviceId}},
                    @{Name="Browser"; Expression={$_.deviceDetail.browser}},
                    @{Name="Operating System"; Expression={$_.deviceDetail.operatingSystem}},
                    @{Name="Compliant"; Expression={$_.deviceDetail.isCompliant}},
                    @{Name="Managed"; Expression={$_.deviceDetail.isManaged}},
                    @{Name="Join Type"; Expression={$_.deviceDetail.trustType}},
                    @{Name="Multifactor authentication result"; Expression={$_.status.additionalDetails}},
                    @{Name="Multifactor authentication auth method"; Expression={$_.mfaDetail.authMethod}},
                    @{Name="Multifactor authentication auth detail"; Expression={$_.mfaDetail.authDetail}},
                    @{Name="Authentication requirement"; Expression={$_.authenticationRequirement}},
                    @{Name="Sign-in identifier"; Expression={$_.signInIdentifier}},
                    @{Name="Session ID"; Expression={$_.sessionId}},
                    @{Name="IP address (seen by resource)"; Expression={$_.ipAddressFromResourceProvider}},
                    @{Name="Through Global Secure Access"; Expression={$_.isThroughGlobalSecureAccess}},
                    @{Name="Global Secure Access IP address"; Expression={$_.globalSecureAccessIpAddress}},
                    @{Name="Autonomous system number"; Expression={$_.autonomousSystemNumber}},
                    @{Name="Flagged for review"; Expression={$_.flaggedForReview}},
                    @{Name="Token issuer type"; Expression={$_.tokenIssuerType}},
                    @{Name="Incoming token type"; Expression={$_.incomingTokenType}},
                    @{Name="Token issuer name"; Expression={$_.tokenIssuerName}},
                    @{Name="Latency"; Expression={$_.processingTimeInMilliseconds}},
                    @{Name="Conditional Access"; Expression={$_.conditionalAccessStatus}},
                    @{Name="Managed Identity type"; Expression={$_.managedServiceIdentity.msiType}},
                    @{Name="Associated Resource Id"; Expression={$_.managedServiceIdentity.associatedResourceId}},
                    @{Name="Federated Token Id"; Expression={$_.managedServiceIdentity.federatedTokenId}},
                    @{Name="Federated Token Issuer"; Expression={$_.managedServiceIdentity.federatedTokenIssuer}}

                # Export to CSV with UTF-8 encoding
                $processedData | Export-Csv -Path $CSVPath -NoTypeInformation -Encoding UTF8

                Write-Log -CaptureOutput -NoConsole "[$UserUPN] ${SignInType}: Successfully exported $totalRecords records to CSV" -Level Success
                return $totalRecords
            } else {
                Write-Log -CaptureOutput -NoConsole "[$UserUPN] ${SignInType}: No records found for the specified date range" -Level Warning
                return 0
            }
        } catch {
            Write-Log -CaptureOutput -NoConsole "[$UserUPN] ${SignInType}: Export failed - $($_.Exception.Message)" -Level Error
            throw "Failed to export $SignInType sign-ins: $($_.Exception.Message)"
        }
    }

    # Main processing logic for each user
    try {
        # Format filenames
        $SafeUPN = $UserUPN -replace '@', '_'

        # Create user-specific folder
        $UserExportPath = Join-Path -Path $ExportPath -ChildPath $SafeUPN
        if (!(Test-Path $UserExportPath)) {
            New-Item -ItemType Directory -Path $UserExportPath | Out-Null
        }

        $InteractiveCSV = "$UserExportPath\InteractiveSignIns_$SafeUPN.csv"
        $NonInteractiveCSV = "$UserExportPath\NonInteractiveSignIns_$SafeUPN.csv"
        $headers = @{ 'ConsistencyLevel' = 'Eventual' }

        # Query to see if the user exist
        $testFilter = "userPrincipalName eq '$UserUPN'&`$select=id,accountEnabled"
        $testresponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users?`$filter=$testFilter" -Headers $headers
        $idvalue = $($testresponse.value).id
        $accountEnabled = $($testresponse.value).accountEnabled

        if ($idvalue -and $accountEnabled -eq $true) {

            # Query to get last password change of the User
            $AllFilter = "userPrincipalName eq '$UserUPN'&`$select=lastPasswordChangeDateTime,city,state,country,department,officeLocation"
            $Allresponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users?`$filter=$AllFilter" -Headers $headers
            $lastPasswordChangeDate = $($Allresponse.value).lastPasswordChangeDateTime
            $city = $($Allresponse.value).city
            $state = $($Allresponse.value).state
            $country = $($Allresponse.value).country
            $department = $($Allresponse.value).department
            $officeLocation = $($Allresponse.value).officeLocation

            # Handle null lastPasswordChangeDate safely
            if ($lastPasswordChangeDate) {
                $lastPasswordChangeDateunixMs = [long](([datetime]$lastPasswordChangeDate).ToUniversalTime().Subtract([datetime]'1970-01-01T00:00:00Z').TotalMilliseconds)
            } else {
                $lastPasswordChangeDateunixMs = $null
                Write-Log -CaptureOutput -NoConsole "[$UserUPN] Warning: lastPasswordChangeDate is null, setting to null in export" -Level Warning
            }

            # Save user info including last password change date
            $UserInfoPath = "$UserExportPath\UserInfo_$SafeUPN.json"
            $userInfo = @{
                "UPN" = $UserUPN
                "LastPasswordChangeDate" = $lastPasswordChangeDateunixMs
                "City" = $city
                "State" = $state
                "Country" = $country
                "Department" = $department
                "OfficeLocation" = $officeLocation
            } | ConvertTo-Json -Depth 5 -Compress

            # Write to file as UTF-8 without BOM
            $utf8NoBom = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::WriteAllText($UserInfoPath, $userInfo, $utf8NoBom)

            $DevicesSelect = "deviceId,registrationDateTime,displayName,deviceOwnership,manufacturer,model,operatingSystem,trustType,enrollmentType"
            $Devicesreponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$idvalue/ownedDevices?`$select=$DevicesSelect" -Headers $headers

            $allDevices = @()

            for ($i = 0; $i -lt $Devicesreponse.value.Count; $i++) {
                $device = $Devicesreponse.value[$i]
                $deviceId = $device.deviceId
                $registrationDateTime = $device.registrationDateTime
                $displayName = $device.displayName
                $deviceOwnership = $device.deviceOwnership
                $manufacturer = $device.manufacturer
                $model = $device.model
                $operatingSystem = $device.operatingSystem
                $trustType = $device.trustType
                $enrollmentType = $device.enrollmentType

                # Handle null registrationDateTime safely
                if ($registrationDateTime) {
                    $registrationDateTimeunixMs = [long](([datetime]$registrationDateTime).ToUniversalTime().Subtract([datetime]'1970-01-01T00:00:00Z').TotalMilliseconds)
                } else {
                    $registrationDateTimeunixMs = $null
                    Write-Log -CaptureOutput -NoConsole "[$UserUPN] Warning: Device '$displayName' has null registrationDateTime, setting to null in export" -Level Warning
                }

                # Create device info object
                $deviceInfo = @{
                    "DeviceId" = $deviceId
                    "RegistrationDateTime" = $registrationDateTimeunixMs
                    "DisplayName" = $displayName
                    "DeviceOwnership" = $deviceOwnership
                    "Manufacturer" = $manufacturer
                    "Model" = $model
                    "OperatingSystem" = $operatingSystem
                    "TrustType" = $trustType
                    "EnrollmentType" = $enrollmentType
                }

                # Add to devices array
                $allDevices += $deviceInfo
            }

            # Save all devices info to single JSON file
            $DevicesInfoPath = "$UserExportPath\DevicesInfo_$SafeUPN.json"
            $devicesInfo = @{
                "UPN" = $UserUPN
                "DeviceCount" = $allDevices.Count
                "Devices" = $allDevices
            } | ConvertTo-Json -Depth 5 -Compress

            # Write to file as UTF-8 without BOM
            $utf8NoBom = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::WriteAllText($DevicesInfoPath, $devicesInfo, $utf8NoBom)

            # Initialize counters for this user
            $interactiveCount = 0
            $nonInteractiveCount = 0

            Write-Log -CaptureOutput -NoConsole "[$UserUPN] Starting sign-in data export..." -Level Info

            # Query for Interactive Sign-Ins
            $InteractiveFilter = "userPrincipalName eq '$UserUPN' and createdDateTime ge $LastMonthStart and createdDateTime le $Today and signInEventTypes/any(t:t eq 'interactiveUser') &$orderby=createdDateTime DESC"
            $InteractiveUri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$InteractiveFilter"

            try {
                $interactiveCount = Export-SignIn -Uri $InteractiveUri -CSVPath $InteractiveCSV -Headers $headers -SignInType "Interactive" -MaxRetries $MaxRetries -UserUPN $UserUPN
            } catch {
                $interactiveCount = 0
            }

            # Query for Non-Interactive Sign-Ins
            $NonInteractiveFilter = "userPrincipalName eq '$UserUPN' and createdDateTime ge $LastMonthStart and createdDateTime le $Today and signInEventTypes/any(t:t eq 'nonInteractiveUser') &$orderby=createdDateTime DESC"
            $NonInteractiveUri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$NonInteractiveFilter"

            try {
                $nonInteractiveCount = Export-SignIn -Uri $NonInteractiveUri -CSVPath $NonInteractiveCSV -Headers $headers -SignInType "Non-Interactive" -MaxRetries $MaxRetries -UserUPN $UserUPN
            } catch {
                $nonInteractiveCount = 0
            }

            return @{
                UPN = $UserUPN
                Success = $true
                Reason = "Export completed successfully"
                InteractiveCount = $interactiveCount
                NonInteractiveCount = $nonInteractiveCount
                ExportPath = $UserExportPath
                LogMessages = $script:outputMessages
            }

        } else {
            # User not found or not active - clean up the user folder
            try {
                if (Test-Path $UserExportPath) {
                    Remove-Item -Path $UserExportPath -Recurse -Force
                    Write-Log -CaptureOutput -NoConsole "[$UserUPN] Removed user folder: $UserExportPath" -Level Info
                }
            } catch {
                Write-Log -CaptureOutput -NoConsole "[$UserUPN] Failed to remove user folder: $($_.Exception.Message)" -Level Warning
            }

            return @{
                UPN = $UserUPN
                Success = $false
                Reason = "User not found or no longer exists or is not active"
                InteractiveCount = 0
                NonInteractiveCount = 0
                LogMessages = $script:outputMessages
            }
        }
    } catch {
        return @{
            UPN = $UserUPN
            Success = $false
            Reason = "Error: $($_.Exception.Message)"
            InteractiveCount = 0
            NonInteractiveCount = 0
            LogMessages = $script:outputMessages
        }
    }
}

# Create runspace jobs for each user
$Jobs = @()
foreach ($UserUPN in $UserUPNArray) {
    Write-Log "Starting parallel processing for user: $UserUPN" -Level Info

    $PowerShell = [powershell]::Create()
    $PowerShell.RunspacePool = $RunspacePool

    # Add the script block and parameters
    [void]$PowerShell.AddScript($ScriptBlock)
    [void]$PowerShell.AddParameter("UserUPN", $UserUPN)
    [void]$PowerShell.AddParameter("LastMonthStart", $LastMonthStart)
    [void]$PowerShell.AddParameter("Today", $Today)
    [void]$PowerShell.AddParameter("ExportPath", $ExportPath)
    [void]$PowerShell.AddParameter("MaxRetries", $MaxRetries)

    # Start the job
    $Job = $PowerShell.BeginInvoke()

    $Jobs += @{
        PowerShell = $PowerShell
        Job = $Job
        UPN = $UserUPN
    }
}

# Wait for all jobs to complete and collect results
Write-Log "Waiting for all parallel jobs to complete..." -Level Info
Write-Log "Press Enter anytime to see current progress..." -Level Info

# Monitor jobs with better progress reporting
$completedJobs = 0
$startTime = Get-Date

# Check jobs in a loop to provide real-time updates
do {
    Start-Sleep -Seconds 2

    # Check if Enter key was pressed
    if ([Console]::KeyAvailable) {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq [ConsoleKey]::Enter) {
            # Display current progress
            $finishedJobs = @($Jobs | Where-Object { $_.Job.IsCompleted })
            $currentCompleted = $finishedJobs.Count
            $percentComplete = [math]::Round(($currentCompleted / $Jobs.Count) * 100, 1)
            $elapsed = (Get-Date) - $startTime
            $activeJobs = $Jobs.Count - $currentCompleted

            Write-Log "=== PROGRESS UPDATE ===" -Level Info
            Write-Log "Overall Progress: $percentComplete% ($currentCompleted/$($Jobs.Count) users completed)" -Level Info
            Write-Log "Elapsed Time: $($elapsed.ToString('mm\:ss'))" -Level Info

            if ($currentCompleted -gt 0 -and $currentCompleted -lt $Jobs.Count) {
                $avgTimePerJob = $elapsed.TotalSeconds / $currentCompleted
                $remainingJobs = $Jobs.Count - $currentCompleted
                $estimatedRemainingTime = [TimeSpan]::FromSeconds($avgTimePerJob * $remainingJobs)
                Write-Log "Estimated Time Remaining: $($estimatedRemainingTime.ToString('mm\:ss'))" -Level Info
            } elseif ($currentCompleted -eq 0) {
                Write-Log "Estimated Time Remaining: Calculating..." -Level Info
            }

            Write-Log "Active Jobs: $activeJobs running, Completed Jobs: $currentCompleted finished" -Level Info
            Write-Log "======================" -Level Info
        }
    }

    $finishedJobs = @($Jobs | Where-Object { $_.Job.IsCompleted })
    $newCompletedCount = $finishedJobs.Count

    if ($newCompletedCount -gt $completedJobs) {
        $completedJobs = $newCompletedCount
        $percentComplete = [math]::Round(($completedJobs / $Jobs.Count) * 100, 1)
        $elapsed = (Get-Date) - $startTime

        if ($completedJobs -lt $Jobs.Count) {
            # Estimate remaining time
            $avgTimePerJob = $elapsed.TotalSeconds / $completedJobs
            $remainingJobs = $Jobs.Count - $completedJobs
            $estimatedRemainingTime = [TimeSpan]::FromSeconds($avgTimePerJob * $remainingJobs)

            Write-Log "Overall Progress: $percentComplete% ($completedJobs/$($Jobs.Count)) - ETA: $($estimatedRemainingTime.ToString('mm\:ss'))" -Level Info
        } else {
            Write-Log "All jobs completed! Total time: $($elapsed.ToString('mm\:ss'))" -Level Success
        }
    }
} while ($completedJobs -lt $Jobs.Count)

# Collect all results
foreach ($JobInfo in $Jobs) {
    try {
        $result = $JobInfo.PowerShell.EndInvoke($JobInfo.Job)
        $exportResults += $result

        # Display captured log messages from the runspace with proper colors
        if ($result.LogMessages) {
            foreach ($logMessage in $result.LogMessages) {
                # Parse the log message to extract level and content
                if ($logMessage -match '^\[.*?\] \[(\w+)\] (.*)$') {
                    $level = $matches[1]
                    $content = $matches[2]

                    # Re-log with proper color formatting
                    Write-Log $content -Level $level
                } else {
                    # Fallback for messages that don't match expected format
                    Write-Output $logMessage
                }
            }
        }

        $processedCount++
        if ($result.Success) {
            $successfulCount++
            Write-Log "Completed $($result.UPN) - Interactive: $($result.InteractiveCount), Non-Interactive: $($result.NonInteractiveCount)" -Level Success
        } else {
            $failedCount++
            Write-Log "Failed $($result.UPN) - $($result.Reason)" -Level Warning
        }

    } catch {
        Write-Log "Error processing job for $($JobInfo.UPN): $($_.Exception.Message)" -Level Error
        $exportResults += @{
            UPN = $JobInfo.UPN
            Success = $false
            Reason = "Job execution error: $($_.Exception.Message)"
            InteractiveCount = 0
            NonInteractiveCount = 0
        }
        $failedCount++
        $processedCount++
    } finally {
        # Clean up
        $JobInfo.PowerShell.Dispose()
    }
}

# Clean up runspace pool
$RunspacePool.Close()
$RunspacePool.Dispose()

# Calculate totals
$totalInteractive = 0
$totalNonInteractive = 0
$successfulExports = @()

foreach ($result in $exportResults) {
    if ($result.Success) {
        $totalInteractive += $result.InteractiveCount
        $totalNonInteractive += $result.NonInteractiveCount
        $successfulExports += $result
    }
}

# Display summary to console
Write-Output ""
Write-Output "=== EXPORT SUMMARY ==="
Write-Log "Total users processed: $processedCount" -Level Info
Write-Log "Successful exports: $successfulCount" -Level Success
Write-Log "Failed exports: $failedCount" -Level $(if ($failedCount -gt 0) { "Warning" } else { "Info" })

if ($successfulCount -gt 0) {
    Write-Log "Total Interactive sign-ins exported: $totalInteractive" -Level Info
    Write-Log "Total Non-Interactive sign-ins exported: $totalNonInteractive" -Level Info
    Write-Log "Files saved to: $ExportPath" -Level Success
    Write-Log "Individual user exports:" -Level Info
    foreach ($result in $successfulExports) {
        Write-Log "- $($result.UPN): Interactive($($result.InteractiveCount)), Non-Interactive($($result.NonInteractiveCount))" -Level Info
        Write-Log "  Path: $($result.ExportPath)" -Level Info
    }
}

if ($failedCount -gt 0) {
    Write-Log "Failed users:" -Level Warning
    $exportResults | Where-Object { !$_.Success } | ForEach-Object {
        Write-Log "  - $($_.UPN): $($_.Reason)" -Level Warning
    }
}

Write-Log "Script execution completed" -Level Success
