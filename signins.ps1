param (
    [string[]]$UserUPNs,
    [string]$StartDate,
    [string]$EndDate,
    [string]$RelativePeriod
)

# Function to validate UPN format
function Confirm-UPN {
    param (
        [string]$UPN
    )
    if ($UPN -notmatch '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
        Write-Output "Error: Invalid UPN format '$UPN'. Exiting script."
        exit 1
    }
}

# Function to export sign-ins to CSV
function Export-SignIns {
    param (
        [string]$Uri,
        [string]$CSVPath,
        [hashtable]$Headers
    )
    try {
        $Response = Invoke-MgGraphRequest -OutputType json -Uri $Uri -Method GET -Headers $Headers
        $Data = $Response | ConvertFrom-Json
        if ($Data.value) {
            $Data.value | Select-Object `
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
                @{Name="Location"; Expression={"$($_.location.city), $($_.location.state), $($_.location.countryOrRegion)"}},
                @{Name="Status"; Expression={if ($_.status.errorCode -eq 0) { "Success" } else { "Interrupted" }}},
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
                @{Name="Federated Token Issuer"; Expression={$_.managedServiceIdentity.federatedTokenIssuer}} |
                Export-Csv -Path $CSVPath -NoTypeInformation
            Write-Output "Sign-ins exported to: $CSVPath"
        } else {
            Write-Output "No sign-ins found."
        }
    } catch {
        Write-Output "Error: Failed to fetch or export sign-ins."
    }
}

# Function to calculate date range based on relative period
function GetDateRangeFromRelativePeriod {
    param (
        [string]$RelativePeriod
    )

    $currentDate = Get-Date
    $startDate = $null
    $endDate = $currentDate.ToString("yyyy-MM-ddT23:59:59Z")

    switch ($RelativePeriod.ToLower()) {
        "lastday" {
            $startDate = $currentDate.AddDays(-1).ToString("yyyy-MM-ddT00:00:00Z")
        }
        "lastweek" {
            $startDate = $currentDate.AddDays(-7).ToString("yyyy-MM-ddT00:00:00Z")
        }
        "lastmonth" {
            $startDate = $currentDate.AddMonths(-1).ToString("yyyy-MM-ddT00:00:00Z")
        }
        "last3months" {
            $startDate = $currentDate.AddMonths(-3).ToString("yyyy-MM-ddT00:00:00Z")
        }
        "last6months" {
            $startDate = $currentDate.AddMonths(-6).ToString("yyyy-MM-ddT00:00:00Z")
        }
        "lastyear" {
            $startDate = $currentDate.AddYears(-1).ToString("yyyy-MM-ddT00:00:00Z")
        }
        default {
            Write-Output "Error: Invalid relative period specified. Using default of last month."
            $startDate = $currentDate.AddMonths(-1).ToString("yyyy-MM-ddT00:00:00Z")
        }
    }

    return @{
        StartDate = $startDate
        EndDate = $endDate
    }
}

# Function to validate date format
function ValidateDateFormat {
    param (
        [string]$DateString
    )

    try {
        $date = [datetime]::ParseExact($DateString, "yyyy-MM-dd", $null)
        return $true
    } catch {
        return $false
    }
}

# If no UPNs are provided, ask the user for input
if (-not $UserUPNs) {
    $UserUPNs = (Read-Host "Enter the UPNs of users (comma-separated, e.g., user1@example.com,user2@example.com)").Split(",")
}

# Validate input
if (-not $UserUPNs -or $UserUPNs.Trim() -eq '') {
    Write-Output "Error: No UPNs provided. Exiting script."
    exit 1
}

# Convert input into an array
$UserUPNArray = $UserUPNs -split '[, ]+' | ForEach-Object { $_.Trim() }

# Validate each UPN format
foreach ($UserUPN in $UserUPNArray) {
    Confirm-UPN -UPN $UserUPN
}

# Define date range (last month)
$LastMonthStart = (Get-Date).AddMonths(-1).ToString("yyyy-MM-ddT00:00:00Z")
$Today = (Get-Date).ToString("yyyy-MM-ddT23:59:59Z")

if ($RelativePeriod) {
    $dateRange = GetDateRangeFromRelativePeriod -RelativePeriod $RelativePeriod
    $LastMonthStart = $dateRange.StartDate
    $Today = $dateRange.EndDate
    Write-Output "Using relative date range: $RelativePeriod"
} elseif ($StartDate -and $EndDate) {
    if (ValidateDateFormat -DateString $StartDate -and ValidateDateFormat -DateString $EndDate) {
        $LastMonthStart = "$StartDate" + "T00:00:00Z"
        $Today = "$EndDate" + "T23:59:59Z"
        Write-Output "Using custom date range: $StartDate to $EndDate"
    } else {
        Write-Output "Error: Invalid date format. Please use YYYY-MM-DD format. Using default of last month."
    }
} else {
    # Prompt for date range if not provided
    $dateOption = Read-Host "Choose date range option (1=Relative, 2=Custom, 3=Default Last Month)"
    switch ($dateOption) {
        "1" {
            $relativeOptions = @("lastday", "lastweek", "lastmonth", "last3months", "last6months", "lastyear")
            $relativeChoice = Read-Host "Choose relative period: 1=Last Day, 2=Last Week, 3=Last Month, 4=Last 3 Months, 5=Last 6 Months, 6=Last Year"
            if ($relativeChoice -match '^[1-6]$') {
                $RelativePeriod = $relativeOptions[$relativeChoice - 1]
                $dateRange = GetDateRangeFromRelativePeriod -RelativePeriod $RelativePeriod
                $LastMonthStart = $dateRange.StartDate
                $Today = $dateRange.EndDate
                Write-Output "Using relative date range: $RelativePeriod"
            } else {
                Write-Output "Invalid choice. Using default of last month."
            }
        }
        "2" {
            $StartDate = Read-Host "Enter start date (YYYY-MM-DD)"
            $EndDate = Read-Host "Enter end date (YYYY-MM-DD)"
            if (ValidateDateFormat -DateString $StartDate -and ValidateDateFormat -DateString $EndDate) {
                $LastMonthStart = "$StartDate" + "T00:00:00Z"
                $Today = "$EndDate" + "T23:59:59Z"
                Write-Output "Using custom date range: $StartDate to $EndDate"
            } else {
                Write-Output "Error: Invalid date format. Using default of last month."
            }
        }
        "3" {
            Write-Output "Using default date range: Last month"
        }
        default {
            Write-Output "Invalid option. Using default date range: Last month"
        }
    }
}

# Set Export Path inside current working directory
$ExportPath = Join-Path -Path (Get-Location) -ChildPath "Exports"

# Ensure Export directory exists
if (!(Test-Path $ExportPath)) {
    try {
        New-Item -ItemType Directory -Path $ExportPath | Out-Null
    } catch {
        Write-Output "Error: Failed to create export directory. Exiting script."
        exit 1
    }
}

# Authenticate with Microsoft Graph (No Import-Module needed)
try {
    Connect-MgGraph -Scopes "AuditLog.Read.All" -NoWelcome
} catch {
    Write-Output "Error: Failed to authenticate with Microsoft Graph. Exiting script."
    exit 1
}

# Process each UPN
foreach ($UserUPN in $UserUPNArray) {
    # Format filenames
    $SafeUPN = $UserUPN -replace '@', '_'
    $InteractiveCSV = "$ExportPath\InteractiveSignIns_$SafeUPN.csv"
    $NonInteractiveCSV = "$ExportPath\NonInteractiveSignIns_$SafeUPN.csv"
    $headers = @{
        'ConsistencyLevel' = 'Eventual'
    }

    Write-Output "Processing UPN: $UserUPN"
    Write-Output ""

    # Query to get last password change of the User
    $LastPasswordFilter = "startswith(userPrincipalName,'$UserUPN')&`$select=lastPasswordChangeDateTime"
    $LastPasswordresponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users?`$filter=$LastPasswordFilter" -Headers $headers
    $lastPasswordChangeDate = $($LastPasswordresponse.value).lastPasswordChangeDateTime
    if ($lastPasswordChangeDate) {
        Write-Output "The last password change date for user $UserUPN is $lastPasswordChangeDate"

        # Query for Interactive Sign-Ins
        Write-Output "Processing for Interactive Sign-Ins"
        $InteractiveFilter = "userPrincipalName eq '$UserUPN' and createdDateTime ge $LastMonthStart and createdDateTime le $Today and signInEventTypes/any(t:t eq 'interactiveUser') &$orderby=createdDateTime DESC"
        $InteractiveUri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$InteractiveFilter"
        Export-SignIns -Uri $InteractiveUri -CSVPath $InteractiveCSV -Headers $headers

        # Query for Non-Interactive Sign-Ins
        Write-Output "Processing for Non-Interactive Sign-Ins"
        $NonInteractiveFilter = "userPrincipalName eq '$UserUPN' and createdDateTime ge $LastMonthStart and createdDateTime le $Today and signInEventTypes/any(t:t eq 'nonInteractiveUser') &$orderby=createdDateTime DESC"
        $NonInteractiveUri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$NonInteractiveFilter"
        Export-SignIns -Uri $NonInteractiveUri -CSVPath $NonInteractiveCSV -Headers $headers

        Write-Output "Sign-ins exported for user $UserUPN. Files are saved in: $ExportPath."
    } else {
        Write-Output "The user $UserUPN does not exist anymore."
    }
    Write-Output " "
    Write-Output "--------------------------------------------------------"
    Write-Output " "
}
