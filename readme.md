# Sign-In Analysis Tool

## Overview

This tool provides a comprehensive solution for exporting, analyzing, and reporting on Microsoft 365 user sign-in activities. It combines PowerShell scripts for data collection with Python-based analysis tools to detect security anomalies and generate detailed reports.

## Features

- **Sign-In Data Collection**: Retrieve interactive and non-interactive sign-in logs from Microsoft Graph API
- **Flexible Date Range Selection**: Choose between relative periods (last day, week, month) or custom date ranges
- **Security Analysis**:
  - Impossible travel detection
  - Brute force attack detection
  - MFA spam detection
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

3. **Environment Configuration**:
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
   - Confirm the GeoDB folder contains the GeoLite2-City.mmdb file
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

This will:
- Export sign-in logs to CSV files in the `Exports` directory
- Include both interactive and non-interactive sign-ins for the specified users
- Use the specified date range (default: last month)

### 2. Analyze Data and Generate Reports

Run the analysis script:
```powershell
python analyse.py -u user1@example.com
```

Or with additional options:
```powershell
python analyse.py -u user1@example.com --mode both --workers 10
```

This will:
- Analyze the collected sign-in data
- Detect security anomalies
- Generate detailed reports in the `reports` directory
- Create an interactive HTML report combining all findings

## Date Range Options

The sign-in collection script supports multiple ways to specify date ranges:

### Relative Periods
- `lastday`: Sign-ins from the last 24 hours
- `lastweek`: Sign-ins from the last 7 days
- `lastmonth`: Sign-ins from the last 30 days (default)
- `last3months`: Sign-ins from the last 90 days
- `last6months`: Sign-ins from the last 180 days
- `lastyear`: Sign-ins from the last 365 days

### Custom Dates
Specify exact start and end dates in YYYY-MM-DD format:
- `-StartDate "2023-01-01"`
- `-EndDate "2023-01-31"`

## Output Files

### Data Collection Output
- `Exports/InteractiveSignIns_<username>.csv`: Interactive sign-in events
- `Exports/NonInteractiveSignIns_<username>.csv`: Non-interactive sign-in events

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

4. **IP Reputation Analysis**:
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

## Configuration

### Analysis Parameters
You can modify these parameters in `analyse.py`:
- `MIN_TIME_SECONDS`: Minimum time difference for speed calculation
- `THRESHOLD_KMH`: Speed threshold for impossible travel detection
- `BRUTE_WINDOW`: Time window for brute force detection
- `BRUTE_MIN_ATTEMPTS`: Minimum attempts for brute force detection
- `MFA_WINDOW`: Time window for MFA spam detection
- `MFA_MIN_ATTEMPTS`: Minimum attempts for MFA spam detection
- `DEFAULT_WORKERS`: Number of parallel workers for analysis

## Troubleshooting

### Common Issues

1. **Missing .env file**:
   - Error: "X .env file not found"
   - Solution: Create the .env file with all required keys

2. **Incomplete .env file**:
   - Error: "X Unable to retrieve ACCOUNT_ID or LICENSE_KEY from .env"
   - Solution: Ensure all required keys are present in the .env file

3. **GeoLite2 database not found**:
   - Error: "GeoIP DB not available"
   - Solution: Run setup.ps1 to download the database

4. **Missing Python dependencies**:
   - Error: ModuleNotFoundError for pandas, geoip2, etc.
   - Solution: Run setup.ps1 to install dependencies

5. **Microsoft Graph authentication issues**:
   - Error: "Failed to authenticate with Microsoft Graph"
   - Solution: Verify your Microsoft Graph permissions and credentials

6. **Invalid date format**:
   - Error: "Error: Invalid date format"
   - Solution: Use YYYY-MM-DD format for custom dates

## Example Workflow

1. **Setup**:
   ```powershell
   .\setup.ps1
   ```

2. **Collect data with relative period**:
   ```powershell
   .\signins.ps1 -UserUPNs "user1@example.com,user2@example.com" -RelativePeriod "lastmonth"
   ```

3. **Analyze data**:
   ```powershell
   python analyse.py -u user1@example.com
   python analyse.py -u user2@example.com
   ```

4. **View reports**:
   Open `reports/all_users_signins_report.html` in a web browser

## Notes

- Ensure you have the necessary permissions to access the Microsoft Graph API
- The script uses the beta endpoint of Microsoft Graph API
- Analysis features require Python and the dependencies listed in requirements.txt
- The GeoLite2 database will be automatically downloaded if not present
- API keys are required for VirusTotal and AbuseIPDB services
- For large datasets, consider increasing the number of workers for faster analysis
- The date range selection provides flexibility to analyze different time periods