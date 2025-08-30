# Sign-In Analysis Tool

## Overview

This tool provides a comprehensive solution for exporting, analyzing, and reporting on Microsoft 365 user sign-in activities. It combines PowerShell scripts for data collection with Python-based analysis tools to detect security anomalies and generate detailed reports.

## Features

- **Sign-In Data Collection**: Retrieve interactive and non-interactive sign-in logs from Microsoft Graph API
- **Parallel Processing**: Process multiple users simultaneously with configurable concurrency (1-20 jobs)
- **Flexible Date Range Selection**: Choose between relative periods (last day, week, month) or custom date ranges
- **Security Analysis**:
  - Impossible travel detection
  - Brute force attack detection
  - MFA spam detection
  - Suspicious devices detection
  - Comprehensive IP reputation analysis
- **Reporting**:
  - Detailed CSV reports for each user
  - Interactive HTML report combining all findings
  - Visual charts and tables for easy analysis

## Prerequisites

### System Requirements

- Windows 10 or later
- PowerShell 5.1 or later
- Python 3.6 or later
- Internet connection for API access
- Appropriate permissions to access Microsoft Graph API (AuditLog.Read.All)

### Software Requirements

1. **Microsoft Graph PowerShell SDK**:

   ```powershell
   Install-Module -Name Microsoft.Graph -RequiredVersion 2.25.0 -Scope CurrentUser
   ```

2. **PowerShell Execution Policy**:

   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process
   ```

3. **Required Account Registrations**:

   You need to create free accounts on the following services to obtain API keys:

   - **MaxMind** (<https://www.maxmind.com/>): Required for GeoLite2 database download
     - Create a free account to get Account ID and License Key
     - Used for geolocation lookups in impossible travel detection

   - **VirusTotal** (<https://www.virustotal.com/>): Required for IP reputation checks
     - Create a free account to get API key
     - Used for malware and threat intelligence on IP addresses

   - **AbuseIPDB** (<https://www.abuseipdb.com/>): Required for IP reputation checks
     - Create a free account to get API key
     - Used for checking IP addresses against abuse reports

4. **Environment Configuration**:

   Create a `.env` file in the project directory with:

   ```env
   ACCOUNT_ID=XXX
   LICENSE_KEY=XXX
   VIRUSTOTAL_API_KEY=XXX
   ABUSEIPDB_API_KEY=XXX
   ```

   Replace XXX with your actual credentials:
   - ACCOUNT_ID and LICENSE_KEY: For GeoLite2 database download
   - VIRUSTOTAL_API_KEY: For VirusTotal IP reputation checks
   - ABUSEIPDB_API_KEY: For AbuseIPDB IP reputation checks

5. **Configuration Parameters**:

   Both the PowerShell collection script (`signins.ps1`) and Python analysis script (`analyse.py`) use the `signins_config.json` file for configuration. You can modify these parameters to customize the tool's behavior:

   **Directory Settings** (`directories`):
   - `reports_dir`: Directory for analysis reports (default: "reports")
   - `exports_dir`: Directory for CSV exports (default: "exports")
   - `geoip_db`: Path to GeoIP database file (default: "geodb/GeoLite2-City.mmdb")

   **Detection Thresholds** (`detection_thresholds`):
   - `threshold_kmh`: Speed threshold for impossible travel detection in km/h (default: 900)
   - `min_time_seconds`: Minimum time between events for analysis in seconds (default: 1)
   - `brute_window_minutes`: Time window for brute force detection in minutes (default: 1)
   - `brute_min_attempts`: Minimum failed attempts to trigger brute force alert (default: 3)
   - `mfa_window_minutes`: Time window for MFA spam detection in minutes (default: 1)
   - `mfa_min_attempts`: Minimum MFA events to trigger spam alert (default: 3)

   **Performance Settings** (`performance`):
   - `default_workers`: Default number of worker threads for analysis (default: 8)
   - `max_retries`: Maximum API request retries for M365 API processing (default: 3)
   - `max_concurrent_jobs`: Default concurrent jobs for M365 API processing (default: 5)

   **Logging Configuration** (`logging`):
   - `level`: Logging level - "Info", "Debug", "Warning", "Error" (default: "Info")
   - `colors_enabled`: Enable ANSI color output in console (default: true)

   **HTML Report Settings** (`html_report`):
   - `output_filename`: Name of the combined HTML report file (default: "all_users_signins_report.html")

   To modify these settings, edit the `signins_config.json` file in the project directory. Changes take effect immediately on the next script run.

## Setup Instructions

1. **Run the setup script**:

   ```powershell
   .\setup.ps1
   ```

   This script will:
   - Create a Python virtual environment
   - Install required Python dependencies
   - Download the GeoLite2 City database
   - Verify environment configuration

2. **Verify setup**:
   - Check that the `venv` directory was created
   - Confirm the geodb folder contains the GeoLite2-City.mmdb file
   - Ensure all API keys are properly configured in .env

## Usage Instructions

### 1. Collect Sign-In Data

Run the sign-in collection script with user UPNs and date range options:

#### Option 1: Using relative period

```powershell
.\signins.ps1 -UserUPNs "user1@example.com,user2@example.com" -RelativePeriod "lastmonth"
```

#### Option 2: Using custom dates

```powershell
.\signins.ps1 -UserUPNs "user1@example.com,user2@example.com" -StartDate "2023-01-01" -EndDate "2023-01-31"
```

#### Option 3: Interactive mode (prompts for dates)

```powershell
.\signins.ps1 -UserUPNs "user1@example.com,user2@example.com"
```

#### Option 4: Without parameters (prompts for UPNs and dates)

```powershell
.\signins.ps1
```

#### Option 5: With parallel processing control

```powershell
.\signins.ps1 -UserUPNs "user1@example.com,user2@example.com" -RelativePeriod "lastweek" -MaxConcurrentJobs 10
```

**Performance Note**: The `-MaxConcurrentJobs` parameter controls how many users are processed simultaneously:

- **Range**: 1-20 (default: 5)
- **Higher values**: Faster processing but more system resources
- **Lower values**: Slower processing but less system load
- **Recommended**: Start with default (5) and increase if needed
- **Verbose Progress**: Shows real-time progress with page-by-page processing details and completion percentages

This will:

- Export sign-in logs to CSV files in the `exports` directory
- Include both interactive and non-interactive sign-ins for the specified users
- Use the specified date range (default: last month)

### 2. Analyze Data and Generate Reports

Run the analysis script:

#### Option 1: Analyze a specific user

```powershell
python analyse.py -u user1@example.com
```

#### Option 2: Interactive user selection

```powershell
python analyse.py
```

This will:

- Show a list of all users with available export data
- Allow you to select single or multiple users
- Support selection options like:
  - Single user: enter the number (e.g., 1)
  - Multiple users: enter numbers separated by commas (e.g., 1,3,5)
  - Range of users: enter range (e.g., `1-5`)
  - All users: enter 'all' or '*'

#### Option 3: With additional options

```powershell
python analyse.py -u user1@example.com --mode both --workers 10
```

This will:

- Analyze the collected sign-in data for selected users
- Detect security anomalies across all selected users
- Generate detailed reports in the `reports` directory for each user
- Create an interactive HTML report combining all findings
- Include user information such as Last Password Change date in the reports

## Date Range Options

The sign-in collection script supports multiple ways to specify date ranges:

### Relative Periods

- `lastday`: Sign-ins from the last 24 hours
- `last3days`: Sign-ins from the last 3 days
- `lastweek`: Sign-ins from the last 7 days
- `lastmonth`: Sign-ins from the last 30 days (default)

### Custom Dates

Specify exact start and end dates in YYYY-MM-DD format:

- `-StartDate "2023-01-01"`
- `-EndDate "2023-01-31"`

## Output Files

### Data Collection Output

- `exports/InteractiveSignIns_<username>.csv`: Interactive sign-in events
- `exports/NonInteractiveSignIns_<username>.csv`: Non-interactive sign-in events

### Analysis Output

- `reports/<username>/`: User-specific analysis reports
- `reports/all_users_signins_report.html`: Combined HTML report for all users

## Analysis Features

### Security Detection

1. **Impossible Travel Detection**:
   - Identifies sign-ins from geographically impossible locations
   - Uses GeoIP database for location information
   - Configurable speed threshold (default: 900 km/h)

2. **Brute Force Detection**:
   - Detects multiple failed sign-in attempts from the same IP
   - Configurable time window (default: 1 minute)
   - Configurable attempt threshold (default: 3 attempts)

3. **MFA Spam Detection**:
   - Identifies patterns of MFA failures or challenges
   - Helps detect potential MFA bypass attempts
   - Configurable time window (default: 1 minute)
   - Configurable attempt threshold (default: 3 attempts)

4. **Suspicious Devices Detection**:
   - Identifies sign-ins from devices not owned by the user
   - Compares sign-in device IDs against user's registered devices
   - Tracks first and last seen dates for suspicious devices
   - Provides device location, user agent, and application details
   - Helps detect potential account compromise from unknown devices

5. **IP Reputation Analysis**:
   - Checks IPs against VirusTotal for malicious activity
   - Checks IPs against AbuseIPDB for abuse reports
   - Provides detailed IP reputation information including:
     - ASN and AS owner information
     - Usage type, ISP, and domain information
     - Hostnames and Tor status

### Reporting Features

- Interactive HTML report with tabbed interface for each user
- Toggleable tables for detailed event information
- Visual charts showing event distribution
- Highlighting of suspicious IPs in reports
- Summary metrics for quick assessment
- User information section including Last Password Change date
- Devices owned by the user
