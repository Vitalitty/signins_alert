<#
.SYNOPSIS
    Sets up the Python environment and GeoLite2 database for signins_alert.

.DESCRIPTION
    This script creates a Python virtual environment, installs dependencies,
    loads .env credentials, and downloads/extracts the GeoLite2-City database.

.NOTES
    Requires Python in PATH and env file with required variables.
#>

# ----- Logging -----
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success", "Debug")]
        [string]$Level = "Info"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        "Info"    { $Host.UI.WriteLine([System.ConsoleColor]::Gray, $Host.UI.RawUI.BackgroundColor, $logMessage) }
        "Warning" { $Host.UI.WriteLine([System.ConsoleColor]::Yellow, $Host.UI.RawUI.BackgroundColor, $logMessage) }
        "Error"   { $Host.UI.WriteLine([System.ConsoleColor]::Red, $Host.UI.RawUI.BackgroundColor, $logMessage) }
        "Success" { $Host.UI.WriteLine([System.ConsoleColor]::Green, $Host.UI.RawUI.BackgroundColor, $logMessage) }
        "Debug"   { $Host.UI.WriteLine([System.ConsoleColor]::Cyan, $Host.UI.RawUI.BackgroundColor, $logMessage) }
        default   { Write-Output $logMessage }
    }
}

# ----- Virtual Environment -----
Write-Log "Creating virtual environment..." -Level Info
try {
    python -m venv venv
    if (!(Test-Path ".\\venv\\Scripts\\Activate.ps1")) {
        Write-Log "Virtual environment activation script not found. Setup failed." -Level Error
        exit 1
    }
    . .\\venv\\Scripts\\Activate.ps1
    Write-Log "Virtual environment activated successfully." -Level Success
} catch {
    Write-Log "Failed to create or activate virtual environment: $($_.Exception.Message)" -Level Error
    exit 1
}

# ----- Dependencies -----
Write-Log "Installing dependencies..." -Level Info
try {
    python -m pip install --upgrade pip --trusted-host pypi.org --trusted-host files.pythonhosted.org
    pip install -r requirements.txt --trusted-host pypi.org --trusted-host files.pythonhosted.org
    Write-Log "Dependencies installed successfully." -Level Success
} catch {
    Write-Log "Dependency installation failed: $($_.Exception.Message)" -Level Error
    exit 1
}

# ----- .env File -----
Write-Log "Loading .env file..." -Level Info
$envFile = ".env"
if (!(Test-Path $envFile)) {
    Write-Log ".env file not found. Please create a file with:" -Level Error
    Write-Log "ACCOUNT_ID=xxxx" -Level Info
    Write-Log "LICENSE_KEY=yyyy" -Level Info
    exit 1
}

# Read .env
$AccountID = $null
$LicenseKey = $null
try {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match "^(.*?)=(.*)$") {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim()
            if ($key -eq "ACCOUNT_ID") { $AccountID = $val }
            if ($key -eq "LICENSE_KEY") { $LicenseKey = $val }
        }
    }
    if (-not $AccountID -or -not $LicenseKey) {
        Write-Log "Unable to retrieve ACCOUNT_ID or LICENSE_KEY from .env" -Level Error
        exit 1
    }
    Write-Log ".env file loaded successfully." -Level Success
} catch {
    Write-Log "Failed to load .env file: $($_.Exception.Message)" -Level Error
    exit 1
}

# ----- GeoLite2 Database -----
Write-Log "Preparing geodb folder..." -Level Info
if (!(Test-Path "geodb")) {
    New-Item -ItemType Directory -Path "geodb" | Out-Null
}

$mmdbPath = "geodb\GeoLite2-City.mmdb"

if (!(Test-Path $mmdbPath)) {
    Write-Log "Downloading GeoLite2 City database..." -Level Info
    $archivePath = "geodb\GeoLite2-City.tar.gz"
    $downloadUrl = "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
    $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${AccountID}:${LicenseKey}"))
    $headers = @{ Authorization = "Basic $base64Auth" }
    try {
        Invoke-WebRequest -Uri $downloadUrl -Headers $headers -OutFile $archivePath -UseBasicParsing
    } catch {
        Write-Log "Download failed. Check your ACCOUNT_ID and LICENSE_KEY." -Level Error
        exit 1
    }

    if (!(Test-Path $archivePath)) {
        Write-Log "Download failed. File not found after download." -Level Error
        exit 1
    }

    Write-Log "Extracting GeoLite2-City.mmdb from archive..." -Level Info
    try {
        $mmdbTarPath = & tar -tzf $archivePath | Where-Object { $_ -like '*GeoLite2-City.mmdb' }
        if ($mmdbTarPath) {
            tar -xzf $archivePath -C geodb $mmdbTarPath
            Remove-Item $archivePath -Force
            # Move mmdb file to geodb directly if extracted in a subfolder
            $extractedPath = Join-Path 'geodb' $mmdbTarPath
            if (Test-Path $extractedPath) {
                Move-Item -Force $extractedPath $mmdbPath
                $subfolder = Split-Path $extractedPath -Parent
                if ($subfolder -ne (Resolve-Path 'geodb')) {
                    Remove-Item -Recurse -Force $subfolder
                }
            }
        } else {
            Write-Log "GeoLite2-City.mmdb not found in archive." -Level Error
            exit 1
        }
    } catch {
        Write-Log "Extraction failed: $($_.Exception.Message)" -Level Error
        exit 1
    }

    if (!(Test-Path $mmdbPath)) {
        Write-Log "GeoLite2-City.mmdb file not found after extraction." -Level Error
        exit 1
    }

    Write-Log "GeoLite2 City database installed successfully." -Level Success
} else {
    Write-Log "GeoLite2 database already present." -Level Info
}

Write-Log "Setup completed!" -Level Success
