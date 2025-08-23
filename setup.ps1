Write-Host "[+] Creating virtual environment..."
python -m venv venv
.\venv\Scripts\Activate.ps1

Write-Host "[+] Installing dependencies..."
python -m pip install --upgrade pip
pip install -r requirements.txt

Write-Host "[+] Loading .env file..."
$envFile = ".env"
if (!(Test-Path -Path $envFile)) {
    Write-Host "X .env file not found. Please create a file with:"
    Write-Host "ACCOUNT_ID=xxxx"
    Write-Host "LICENSE_KEY=yyyy"
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
    Write-Host "X Unable to retrieve ACCOUNT_ID or LICENSE_KEY from .env"
    exit 1
}

Write-Host "[+] Preparing GeoDB folder..."
if (!(Test-Path -Path "GeoDB")) {
    New-Item -ItemType Directory -Path "GeoDB" | Out-Null
}

$mmdbPath = "GeoDB\GeoLite2-City.mmdb"

if (!(Test-Path -Path $mmdbPath)) {

    Write-Host "[+] Downloading GeoLite2 City database via curl.exe..."
    $zipPath = "GeoDB\GeoLite2-City.tar.gz"
    $curlUser = "${AccountID}:${LicenseKey}"

    curl.exe -L -u $curlUser "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz" -o $zipPath

    if (!(Test-Path -Path $zipPath)) {
        Write-Host "X Download failed. Check your ACCOUNT_ID and LICENSE_KEY."
        exit 1
    }

    Write-Host "[+] Extracting..."
    # Expand-Archive -Path $zipPath -DestinationPath "GeoDB" -Force
    & tar.exe -xzf $zipPath -C GeoDB

    $mmdb = Get-ChildItem -Path "GeoDB" -Recurse -Filter "GeoLite2-City.mmdb" | Select-Object -First 1
    if ($mmdb) {
        Move-Item -Path $mmdb.FullName -Destination $mmdbPath -Force
    } else {
        Write-Host "X Error: GeoLite2-City.mmdb file not found in the archive."
        exit 1
    }

    Remove-Item $zipPath -Force
    Get-ChildItem "GeoDB" -Recurse | Where-Object { $_.PSIsContainer -and $_.FullName -ne (Resolve-Path "GeoDB") } | Remove-Item -Recurse -Force

    Write-Host "[V] GeoLite2 City database installed successfully."
} else {
    Write-Host "[+] GeoLite2 database already present."
}

Write-Host "[V] Setup completed!"
