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
- User information section including Last Password Change date