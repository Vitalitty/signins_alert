Write-Output "[+] Creating virtual environment..."
python -m venv venv
.\venv\Scripts\Activate.ps1

Write-Output "[+] Installing dependencies..."
python -m pip install --upgrade pip
pip install -r requirements.txt

Write-Output "[+] Loading .env file..."
$envFile = ".env"
if (!(Test-Path -Path $envFile)) {
    Write-Output "X .env file not found. Please create a file with:"
    Write-Output "ACCOUNT_ID=xxxx"
    Write-Output "LICENSE_KEY=yyyy"
    exit 1
}

# Read .env
Get-Content $envFile | ForEach-Object {
    if ($_ -match "^(.*?)=(.*)$") {
        $key = $matches[1].Trim()
        $val = $matches[2].Trim()
        if ($key -eq "ACCOUNT_ID") { $AccountID = $val }
        if ($key -eq "LICENSE_KEY") { $LicenseKey = $val }
    }
}

if (-not $AccountID -or -not $LicenseKey) {
    Write-Output "X Unable to retrieve ACCOUNT_ID or LICENSE_KEY from .env"
    exit 1
}

Write-Output "[+] Preparing geodb folder..."
if (!(Test-Path -Path "geodb")) {
    New-Item -ItemType Directory -Path "geodb" | Out-Null
}

$mmdbPath = "geodb\GeoLite2-City.mmdb"

if (!(Test-Path -Path $mmdbPath)) {

    Write-Output "[+] Downloading GeoLite2 City database via curl.exe..."
    $zipPath = "geodb\GeoLite2-City.tar.gz"
    $curlUser = "${AccountID}:${LicenseKey}"

    curl.exe -L -u $curlUser "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz" -o $zipPath

    if (!(Test-Path -Path $zipPath)) {
        Write-Output "X Download failed. Check your ACCOUNT_ID and LICENSE_KEY."
        exit 1
    }

    Write-Output "[+] Extracting..."
    & tar.exe -xzf $zipPath -C geodb

    $mmdb = Get-ChildItem -Path "geodb" -Recurse -Filter "GeoLite2-City.mmdb" | Select-Object -First 1
    if ($mmdb) {
        Move-Item -Path $mmdb.FullName -Destination $mmdbPath -Force
    } else {
        Write-Output "X Error: GeoLite2-City.mmdb file not found in the archive."
        exit 1
    }

    Remove-Item $zipPath -Force
    Get-ChildItem "geodb" -Recurse | Where-Object { $_.PSIsContainer -and $_.FullName -ne (Resolve-Path "geodb") } | Remove-Item -Recurse -Force

    Write-Output "[V] GeoLite2 City database installed successfully."
} else {
    Write-Output "[+] GeoLite2 database already present."
}

Write-Output "[V] Setup completed!"
