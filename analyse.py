#!/usr/bin/env python3
print("Sign-In Analysis Tool - Loading libraries...")

from pathlib import Path
import argparse
import logging
import pandas as pd
import numpy as np
import geoip2.database
import ipaddress
from geoip2.errors import AddressNotFoundError
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import subprocess
import sys
from dotenv import load_dotenv
import os
from datetime import datetime, timezone

print("Initialization complete!")

# Disable InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----- Load Configuration -----
CONFIG_FILE = Path("signins_config.json")


def load_config():
    """Load configuration from signins_config.json file."""
    # Define default configuration structure
    default_config = {
        "directories": {
            "reports_dir": "reports",
            "exports_dir": "exports",
            "geoip_db": "geodb/GeoLite2-City.mmdb"
        },
        "detection_thresholds": {
            "min_time_seconds": 1,
            "threshold_kmh": 900,
            "brute_window_minutes": 1,
            "brute_min_attempts": 3,
            "mfa_window_minutes": 1,
            "mfa_min_attempts": 3
        },
        "performance": {
            "default_workers": 8
        },
        "logging": {
            "level": "Info",
            "colors_enabled": True
        }
    }

    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)

            # Validate and merge with defaults to ensure all required fields exist
            def merge_config(default, loaded):
                """Recursively merge loaded config with defaults"""
                result = default.copy()
                if isinstance(loaded, dict):
                    for key, value in loaded.items():
                        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                            result[key] = merge_config(result[key], value)
                        else:
                            result[key] = value
                return result

            config = merge_config(default_config, config)

            # Validate specific config values
            valid_log_levels = ["Error", "Warning", "Info", "Success", "Debug"]
            if config["logging"]["level"] not in valid_log_levels:
                print(f"Warning: Invalid logging level '{config['logging']['level']}'. Using 'Info'.")
                config["logging"]["level"] = "Info"

            if not isinstance(config["logging"]["colors_enabled"], bool):
                print("Warning: Invalid colors_enabled value. Using True.")
                config["logging"]["colors_enabled"] = True

            return config

        except Exception as e:
            print(f"Warning: Error loading config file {CONFIG_FILE}: {e}")
            print("Using hardcoded defaults.")
    else:
        print(f"Warning: Config file {CONFIG_FILE} not found. Using hardcoded defaults.")

    # Return complete default configuration if config file is missing or invalid
    return default_config


# Load configuration
config = load_config()

# ----- config -----
MIN_TIME_SECONDS = config["detection_thresholds"]["min_time_seconds"]
THRESHOLD_KMH = config["detection_thresholds"]["threshold_kmh"]
BRUTE_WINDOW = pd.Timedelta(minutes=config["detection_thresholds"]["brute_window_minutes"])
BRUTE_MIN_ATTEMPTS = config["detection_thresholds"]["brute_min_attempts"]
MFA_WINDOW = pd.Timedelta(minutes=config["detection_thresholds"]["mfa_window_minutes"])
MFA_MIN_ATTEMPTS = config["detection_thresholds"]["mfa_min_attempts"]
GEOIP_DB = Path(config["directories"]["geoip_db"])
REPORT_DIR = Path(config["directories"]["reports_dir"])
REPORT_DIR.mkdir(exist_ok=True)
DEFAULT_WORKERS = config["performance"]["default_workers"]
EXPORTS_DIR = Path(config["directories"]["exports_dir"])


# ----- logging -----
def write_log(message, level="Info"):
    """Custom logging function with timestamp and colors matching PowerShell format."""
    # Get logging configuration
    log_config = config.get("logging", {})
    min_log_level = log_config.get("level", "Info")
    colors_enabled = log_config.get("colors_enabled", True)

    # Define log level hierarchy for filtering
    level_hierarchy = {"Error": 0, "Warning": 1, "Info": 2, "Success": 2, "Debug": 3}

    # Check if this message should be logged based on configured level
    if level_hierarchy.get(level, 2) > level_hierarchy.get(min_log_level, 2):
        return  # Skip logging if level is below configured minimum

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] [{level}] {message}"

    # Apply colors only if enabled in config
    if colors_enabled:
        # Color codes for Windows/Unix terminals
        if sys.platform == "win32":
            # Windows ANSI color codes (works with modern Windows 10/11)
            color_map = {
                "Info": "\033[37m",       # White
                "Warning": "\033[33m",    # Yellow
                "Error": "\033[31m",      # Red
                "Success": "\033[32m",    # Green
                "Debug": "\033[36m"       # Cyan
            }
            reset_color = "\033[0m"
        else:
            # Unix/Linux color codes
            color_map = {
                "Info": "\033[0;37m",     # White
                "Warning": "\033[0;33m",  # Yellow
                "Error": "\033[0;31m",    # Red
                "Success": "\033[0;32m",   # Green
                "Debug": "\033[0;36m"     # Cyan
            }
            reset_color = "\033[0m"

        color = color_map.get(level, color_map["Info"])
        print(f"{color}{log_message}{reset_color}")
    else:
        print(log_message)


# Keep standard logging for external libraries, but set to WARNING to reduce noise
logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")

# ----- Load API keys -----
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# ----- Log Configuration Summary -----
write_log(f"Using configuration: reports_dir='{REPORT_DIR}', exports_dir='{EXPORTS_DIR}', geoip_db='{GEOIP_DB}', "
          + f"threshold_kmh={THRESHOLD_KMH}, min_time_seconds={MIN_TIME_SECONDS}, "
          + f"brute_window_minutes={config['detection_thresholds']['brute_window_minutes']}, brute_min_attempts={BRUTE_MIN_ATTEMPTS}, "
          + f"mfa_window_minutes={config['detection_thresholds']['mfa_window_minutes']}, mfa_min_attempts={MFA_MIN_ATTEMPTS}, "
          + f"default_workers={DEFAULT_WORKERS}, log_level='{config['logging']['level']}', colors_enabled={config['logging']['colors_enabled']}", "Info")


# ----- user selection functions -----
def get_available_users(exports_dir: Path):
    """Get list of available users from the exports directory."""
    print("Scanning exports directory for available users...")
    users = []
    if not exports_dir.exists():
        print(f"Exports directory not found: {exports_dir}")
        return users

    directories = [item for item in exports_dir.iterdir() if item.is_dir()]
    if not directories:
        print("No user directories found in exports folder")
        return users

    print(f"Checking {len(directories)} directories for complete datasets...")

    for item in directories:
        # Check if this folder contains sign-in CSV files
        interactive_csv = item / f"InteractiveSignIns_{item.name}.csv"
        non_interactive_csv = item / f"NonInteractiveSignIns_{item.name}.csv"
        if interactive_csv.exists() and non_interactive_csv.exists():
            users.append(item.name)

    if users:
        print(f"Found {len(users)} users with complete export data.")
    else:
        print("No users found with complete export data (both CSV files required)")
    return sorted(users)


def select_users_interactive(available_users):
    """Interactive user selection with support for multiple users."""
    if not available_users:
        print("No users with complete export data found in the exports directory.")
        return []

    print("\n" + "=" * 60)
    print("AVAILABLE USERS WITH EXPORT DATA")
    print("=" * 60)

    # Display users in columns for better readability
    for i, user in enumerate(available_users, 1):
        print(f"{i:2d}. {user}")

    print("\n" + "-" * 60)
    print("SELECTION OPTIONS:")
    print("  Single user:     Enter number (e.g., 1)")
    print("  Multiple users:  Enter numbers separated by commas (e.g., 1,3,5)")
    print("  Range of users:  Enter range (e.g., 1-5)")
    print("  All users:       Enter 'all' or '*'")
    print("  Search users:    Enter 's' to search by name")
    print("  Cancel:          Enter 'q' or 'quit'")
    print("-" * 60)

    while True:
        selection = input("\nYour choice: ").strip()

        if selection.lower() in ['q', 'quit']:
            return []

        if selection.lower() == 's':
            # Search functionality
            search_term = input("Enter search term: ").strip().lower()
            matching_users = [user for user in available_users if search_term in user.lower()]
            if matching_users:
                print(f"\nMatching users: {', '.join(matching_users)}")
                confirm = input("Process these users? (y/n): ").strip().lower()
                if confirm in ['y', 'yes']:
                    return matching_users
            else:
                print("No users found matching your search.")
            continue

        if selection.lower() in ['all', '*']:
            print(f"\nSelected ALL {len(available_users)} users")
            confirm = input("Proceed with all users? (y/n): ").strip().lower()
            if confirm in ['y', 'yes']:
                return available_users
            continue

        try:
            selected_indices = []

            # Handle ranges (e.g., 1-5)
            if '-' in selection:
                parts = selection.split('-')
                if len(parts) == 2:
                    start, end = int(parts[0].strip()), int(parts[1].strip())
                    selected_indices.extend(range(start - 1, end))
            else:
                # Handle comma-separated numbers
                for part in selection.split(','):
                    part = part.strip()
                    if part:
                        idx = int(part)
                        if 1 <= idx <= len(available_users):
                            selected_indices.append(idx - 1)
                        else:
                            raise ValueError(f"Invalid selection: {idx}")

            if selected_indices:
                # Remove duplicates and sort
                selected_indices = sorted(list(set(selected_indices)))
                selected_users = [available_users[i] for i in selected_indices]
                print(f"\nSelected users ({len(selected_users)}):")
                for user in selected_users:
                    print(f"  V {user}")
                confirm = input("\nProceed with these users? (y/n): ").strip().lower()
                if confirm in ['y', 'yes']:
                    return selected_users
            else:
                print("No valid selection made.")

        except ValueError as e:
            print(f"Invalid input: {e}")

        print("Please try again.")


def select_mode_interactive():
    """Interactive mode selection."""
    print("\n" + "=" * 50)
    print("ANALYSIS MODE SELECTION")
    print("=" * 50)
    print("Available analysis modes:")
    print("  1. Combined    - Merge interactive + non-interactive data for analysis")
    print("  2. Separate    - Analyze interactive and non-interactive data separately")
    print("  3. Both        - Run both combined and separate analysis (comprehensive)")
    print("  'q' or 'quit'  - Cancel the operation")
    print("-" * 50)
    print("Mode descriptions:")
    print("  • Combined: Best for overall security analysis (brute-force, MFA attacks)")
    print("  • Separate: Best for comparing interactive vs non-interactive patterns")
    print("  • Both: Most comprehensive analysis (recommended for thorough investigation)")
    print("-" * 50)

    while True:
        choice = input("Select analysis mode (1-3): ").strip()

        if choice == "1":
            print("Selected: Combined mode")
            return "combined"
        elif choice == "2":
            print("Selected: Separate mode")
            return "separate"
        elif choice == "3":
            print("Selected: Both modes")
            return "both"
        elif choice.lower() in ['q', 'quit']:
            return None
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


# ----- helpers -----
def safe_read_csv(path: Path, parse_dates=None, dtypes=None):
    if not path.exists():
        raise FileNotFoundError(f"{path} not found")
    # pass parse_dates and dtypes if provided
    kwargs = {}
    if parse_dates is not None:
        kwargs["parse_dates"] = parse_dates
    if dtypes is not None:
        kwargs["dtype"] = dtypes
    # Set low_memory=False to avoid DtypeWarning for mixed types
    kwargs["low_memory"] = False
    return pd.read_csv(path, **kwargs)


def haversine_vec(lat1, lon1, lat2, lon2):
    """Returns distance in km between arrays/values (numpy arrays supported)."""
    lat1, lon1, lat2, lon2 = map(np.radians, (lat1, lon1, lat2, lon2))
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = np.sin(dlat / 2.0) ** 2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon / 2.0) ** 2
    c = 2 * np.arcsin(np.sqrt(a))
    R = 6371.0
    return R * c


def geoip_lookup_bulk(reader, ips, workers=DEFAULT_WORKERS):
    """Returns dict ip -> (lat, lon) or None, parallelized."""
    results = {}
    # properly convert to Series, remove NaN/empty values and keep unique
    ips_series = pd.Series(ips).dropna().astype(str).str.strip()
    # remove empty strings
    ips_series = ips_series[ips_series != ""]
    unique_ips = ips_series.unique().tolist()

    # keep only globally-routable IPs

    def _is_global(ip):
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False
    unique_ips = [ip for ip in unique_ips if _is_global(ip)]

    def lookup(ip):
        try:
            resp = reader.city(ip)
            if resp.location.latitude is None or resp.location.longitude is None:
                return ip, None
            return ip, (resp.location.latitude, resp.location.longitude)
        except AddressNotFoundError:
            return ip, None
        except Exception as e:
            # Keep this as debug level since it's not critical
            if hasattr(logging, 'debug'):
                logging.debug("GeoIP failed for %s: %s", ip, e)
            return ip, None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(lookup, ip): ip for ip in unique_ips}
        for fut in as_completed(futures):
            ip, coord = fut.result()
            results[ip] = coord
    return results


def sliding_window_alerts(times, min_attempts, window_timedelta):
    """
    Return list of (start, end, count) bursts where >= min_attempts occur within the window.
    Overlapping windows are merged into a single burst.
    """
    ts = sorted(t for t in times if pd.notna(t))
    if not ts:
        return []
    left = 0
    raw = []  # (start, end, count)
    for right in range(len(ts)):
        while ts[right] - ts[left] > window_timedelta:
            left += 1
        count = right - left + 1
        if count >= min_attempts:
            raw.append((ts[left], ts[right], count))
    # merge overlapping/adjacent windows
    if not raw:
        return []
    merged = [list(raw[0])]
    for s, e, c in raw[1:]:
        if s <= merged[-1][1]:  # overlap/adjacent
            merged[-1][1] = max(merged[-1][1], e)
            merged[-1][2] = max(merged[-1][2], c)
        else:
            merged.append([s, e, c])
    return [tuple(m) for m in merged]


# ----- IP enrichment -----
def query_virustotal(ip):
    if not VT_API_KEY:
        return "No VT key"
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=10, verify=False)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            asn = data.get("asn", "N/A")
            as_owner = data.get("as_owner", "N/A")
            return f"malicious:{stats.get('malicious',0)};suspicious:{stats.get('suspicious',0)};asn:{asn};as_owner:{as_owner}"
        else:
            return f"Error:{resp.status_code}"
    except Exception as e:
        return f"Exception:{e}"


def query_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return "No AbuseIPDB key"
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10, verify=False)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return (f"score:{data.get('abuseConfidenceScore',0)};"
                    f"reports:{data.get('totalReports',0)};"
                    f"usageType:{data.get('usageType','N/A')};"
                    f"isp:{data.get('isp','N/A')};"
                    f"domain:{data.get('domain','N/A')};"
                    f"hostnames:{','.join(data.get('hostnames',[])) if data.get('hostnames') else 'N/A'};"
                    f"isTor:{data.get('isTor',False)}")
        else:
            return f"Error:{resp.status_code}"
    except Exception as e:
        return f"Exception:{e}"


# ----- Detection Functions -----
def detect_impossible_travel(df: pd.DataFrame, username: str, mode: str):
    """Detect impossible travel anomalies based on geographic distance and time."""
    user_report_dir = REPORT_DIR / username

    mask = df["lat"].notna() & df["lon"].notna() & df["prev_lat"].notna() & df["prev_lon"].notna()
    dists = np.full(len(df), np.nan)
    if mask.any():
        dists[mask] = haversine_vec(
            df.loc[mask, "prev_lat"].values,
            df.loc[mask, "prev_lon"].values,
            df.loc[mask, "lat"].values,
            df.loc[mask, "lon"].values
        )
    df["distance_km"] = dists
    df["time_diff_s"] = (df["date_utc"] - df["prev_time"]).dt.total_seconds()
    df.loc[df["time_diff_s"].abs() < MIN_TIME_SECONDS, "time_diff_s"] = np.nan
    df["time_diff_h"] = df["time_diff_s"] / 3600.0
    df["speed_kmh"] = df["distance_km"] / df["time_diff_h"]

    # Clean up invalid divisions (NaN, inf from division by zero)
    df["speed_kmh"] = df["speed_kmh"].replace([np.inf, -np.inf], np.nan)
    df["speed_kmh"] = df["speed_kmh"].fillna(0)

    impossible = df[df["speed_kmh"] > THRESHOLD_KMH].copy()
    impossible_count = len(impossible)
    write_log(f"[{mode}] Impossible travel anomalies: {impossible_count}", "Info")
    if impossible_count > 0:
        # Select only useful columns for impossible travel analysis
        useful_columns = [
            "date_utc", "username", "ip", "location", "application",
            "user_agent", "device_id", "browser", "operating_system",
            "prev_time", "lat", "lon", "prev_lat", "prev_lon",
            "distance_km", "time_diff_h", "speed_kmh"
        ]
        # Only include columns that exist in the dataframe
        available_columns = [col for col in useful_columns if col in impossible.columns]
        impossible_filtered = impossible[available_columns].copy()
        impossible_filtered.to_csv(user_report_dir / f"impossible_travel_{username}_{mode}.csv", index=False)

    return impossible_count


def detect_brute_force(df: pd.DataFrame, username: str, mode: str):
    """Detect brute-force attacks based on single-factor authentication failures."""
    user_report_dir = REPORT_DIR / username

    # Clean Authentication requirement column
    auth_req_col = "Authentication requirement"
    df[auth_req_col] = df[auth_req_col].fillna("").astype(str)

    # Brute-force - only consider singleFactorAuthentication with errors
    brute_condition = (
        (df[auth_req_col] == "singleFactorAuthentication")
        & (df.get("Sign-in error code", 0) != 0)
    )
    failures = df[brute_condition].copy()
    brute_alerts = []
    for ip, group in failures.groupby("ip"):
        times = group["date_utc"].dropna().tolist()
        alerts = sliding_window_alerts(times, BRUTE_MIN_ATTEMPTS, BRUTE_WINDOW)
        for a, b, c in alerts:
            brute_alerts.append({"ip": ip, "start_time": a, "end_time": b, "count": c, "type": "brute-force"})
    brute_count = len(brute_alerts)
    write_log(f"[{mode}] Brute-force alerts: {brute_count}", "Info")
    if brute_alerts:
        pd.DataFrame(brute_alerts).to_csv(user_report_dir / f"brute_alerts_{username}_{mode}.csv", index=False)

    return brute_count


def detect_mfa_spam(df: pd.DataFrame, username: str, mode: str):
    """Detect MFA spam attacks based on multi-factor authentication failures."""
    user_report_dir = REPORT_DIR / username

    # Clean Authentication requirement column
    auth_req_col = "Authentication requirement"
    df[auth_req_col] = df[auth_req_col].fillna("").astype(str)

    # MFA - only consider multiFactorAuthentication with errors
    mfa_alerts = []
    mfa_condition = (
        (df[auth_req_col] == "multiFactorAuthentication")
        & (df.get("Sign-in error code", 0) != 0)
    )
    mfa_fail = df[mfa_condition].copy()
    for ip, group in mfa_fail.groupby("ip"):
        times = group["date_utc"].dropna().tolist()
        alerts = sliding_window_alerts(times, MFA_MIN_ATTEMPTS, MFA_WINDOW)
        for a, b, c in alerts:
            mfa_alerts.append({"ip": ip, "start_time": a, "end_time": b, "count": c, "type": "mfa-spam"})
    mfa_count = len(mfa_alerts)
    write_log(f"[{mode}] MFA alerts: {mfa_count}", "Info")
    if mfa_alerts:
        pd.DataFrame(mfa_alerts).to_csv(user_report_dir / f"mfa_alerts_{username}_{mode}.csv", index=False)

    return mfa_count


def detect_suspicious_devices(df: pd.DataFrame, username: str, mode: str):
    """Detect devices used in sign-ins that are not owned by the user."""
    user_report_dir = REPORT_DIR / username
    exports_dir = EXPORTS_DIR / username

    # Load user's owned devices
    devices_info_path = exports_dir / f"DevicesInfo_{username}.json"
    owned_device_ids = set()

    if devices_info_path.exists():
        try:
            with open(devices_info_path, 'r', encoding='utf-8') as f:
                device_data = json.load(f)
                for device in device_data.get("Devices", []):
                    device_id = device.get("DeviceId")
                    if device_id:
                        owned_device_ids.add(device_id)
            write_log(f"Loaded {len(owned_device_ids)} owned devices for {username}", "Info")
        except Exception as e:
            write_log(f"Error loading device info for {username}: {e}", "Warning")
            return 0
    else:
        write_log(f"No device info found for {username} at {devices_info_path}", "Warning")
        return 0

    # Find the device ID column
    device_col = None
    for col in df.columns:
        if "device" in col.lower() and "id" in col.lower():
            device_col = col
            break

    if device_col is None:
        write_log(f"No device ID column found in {mode} data", "Warning")
        return 0

    # Collect suspicious devices
    suspicious_devices = []
    device_occurrences = {}

    for _, row in df.iterrows():
        device_id = row.get(device_col)
        if pd.isna(device_id) or str(device_id).strip() == "":
            continue

        device_id = str(device_id).strip()

        # If device is not owned by user, it's suspicious
        if device_id not in owned_device_ids:
            current_date = row.get("date_utc", "Unknown")
            if device_id not in device_occurrences:
                device_occurrences[device_id] = {
                    "device_id": device_id,
                    "first_seen": current_date,
                    "last_seen": current_date,
                    "ip": row.get("ip", "Unknown"),
                    "location": row.get("location", "Unknown"),
                    "user_agent": row.get("user_agent", "Unknown"),
                    "application": row.get("application", "Unknown"),
                    "occurrences": 0
                }
            else:
                # Update last_seen date if this occurrence is more recent
                device_occurrences[device_id]["last_seen"] = current_date
            device_occurrences[device_id]["occurrences"] += 1

    # Convert to list for CSV output
    for device_id, info in device_occurrences.items():
        suspicious_devices.append(info)

    # Save results
    suspicious_devices_count = len(suspicious_devices)
    write_log(f"[{mode}] Suspicious devices: {suspicious_devices_count}", "Info")

    if suspicious_devices:
        output_path = user_report_dir / f"suspicious_devices_{username}_{mode}.csv"
        pd.DataFrame(suspicious_devices).to_csv(output_path, index=False)

    return suspicious_devices_count


# ----- core analysis -----
def prepare_dataframe(df: pd.DataFrame, ip_map: dict):
    """Prepare DataFrame with common fields needed for analysis."""
    # Prepare DataFrame with common fields
    df["ip"] = df.get("IP address", pd.Series([None] * len(df))).apply(lambda x: str(x).strip() if pd.notna(x) and str(x).strip() != "" else None)
    df["Coordinates"] = df["ip"].map(ip_map)
    df["lat"] = df["Coordinates"].apply(lambda x: x[0] if isinstance(x, (list, tuple)) and len(x) > 0 else np.nan)
    df["lon"] = df["Coordinates"].apply(lambda x: x[1] if isinstance(x, (list, tuple)) and len(x) > 1 else np.nan)

    # Standardize column names to snake_case
    df["date_utc"] = df["Date (UTC)"]
    df["username"] = df.get("Username", df.get("User", ""))
    df["location"] = df.get("Location", "")
    df["application"] = df.get("Application", "")
    df["user_agent"] = df.get("User agent", "")
    df["device_id"] = df.get("Device ID", "")
    df["browser"] = df.get("Browser", "")
    df["operating_system"] = df.get("Operating System", "")

    df = df.sort_values("date_utc").reset_index(drop=True)
    df["prev_time"] = df["date_utc"].shift(1)
    df["prev_lat"] = df["lat"].shift(1)
    df["prev_lon"] = df["lon"].shift(1)

    # Prepare data for brute force and MFA detection
    df["Status"] = df.get("Status", pd.Series([""] * len(df))).fillna("").astype(str)
    if "Sign-in error code" in df.columns:
        df["Sign-in error code"] = pd.to_numeric(df["Sign-in error code"], errors="coerce").fillna(0).astype(int)

    return df


def run_detection_functions(df: pd.DataFrame, username: str, mode: str, detection_functions: list):
    """Run specified detection functions on prepared DataFrame."""
    functions_str = ", ".join(detection_functions)
    write_log(f"Analysis ({mode}) launched with [{functions_str}]: {len(df)} events", "Info")

    # Ensure per-user report folder exists
    user_report_dir = REPORT_DIR / username
    user_report_dir.mkdir(parents=True, exist_ok=True)

    # Initialize results
    results = {
        "events": len(df),
        "impossible_count": 0,
        "brute_count": 0,
        "mfa_count": 0,
        "suspicious_devices_count": 0
    }

    # Run specified detection functions
    for func_name in detection_functions:
        if func_name == "impossible_travel":
            results["impossible_count"] = detect_impossible_travel(df, username, mode)
        elif func_name == "brute_force":
            results["brute_count"] = detect_brute_force(df, username, mode)
        elif func_name == "mfa_spam":
            results["mfa_count"] = detect_mfa_spam(df, username, mode)
        elif func_name == "suspicious_devices":
            results["suspicious_devices_count"] = detect_suspicious_devices(df, username, mode)
        else:
            write_log(f"Unknown detection function: {func_name}", "Warning")

    return results


# ----- Suspicious IP CSV -----
def generate_suspicious_ips_csv(username):
    user_report_dir = REPORT_DIR / username
    alert_files = list(user_report_dir.glob("*.csv"))

    # Collect unique IPs and reasons from alert CSVs
    ip_reasons = {}
    for f in alert_files:
        fname = f.name.lower()
        if fname.startswith("impossible_travel_"):
            reason = "impossible-travel"
            ip_col = "ip"
        elif fname.startswith("brute_alerts_"):
            reason = "brute-force"
            ip_col = "ip"
        elif fname.startswith("mfa_alerts_"):
            reason = "mfa-spam"
            ip_col = "ip"
        elif fname.startswith("suspicious_devices_"):
            reason = "suspicious-device"
            ip_col = "ip"
        else:
            continue

        df = pd.read_csv(f)
        for _, row in df.iterrows():
            ip = row.get(ip_col, None)
            if pd.isna(ip) or str(ip).strip() == "":
                continue
            ip = str(ip).strip()
            if ip not in ip_reasons:
                ip_reasons[ip] = set()
            ip_reasons[ip].add(reason)

    records = []

    # Helper for enrichment

    def enrich_ip(ip):
        vt_info = query_virustotal(ip)
        abuse_info = query_abuseipdb(ip)
        reason_str = ",".join(sorted(ip_reasons[ip]))

        # Parse VT info
        vt_parts = vt_info.split(';')
        vt_dict = {}
        for part in vt_parts:
            if ':' in part:
                key, value = part.split(':', 1)
                vt_dict[key] = value

        # Parse AbuseIPDB info
        abuse_parts = abuse_info.split(';')
        abuse_dict = {}
        for part in abuse_parts:
            if ':' in part:
                key, value = part.split(':', 1)
                abuse_dict[key] = value

        return {
            "ip": ip,
            "reason": reason_str,
            "virustotal_malicious": vt_dict.get('malicious', '0'),
            "virustotal_suspicious": vt_dict.get('suspicious', '0'),
            "virustotal_asn": vt_dict.get('asn', 'N/A'),
            "virustotal_as_owner": vt_dict.get('as_owner', 'N/A'),
            "abuseipdb_score": abuse_dict.get('score', '0'),
            "abuseipdb_reports": abuse_dict.get('reports', '0'),
            "abuseipdb_usageType": abuse_dict.get('usageType', 'N/A'),
            "abuseipdb_isp": abuse_dict.get('isp', 'N/A'),
            "abuseipdb_domain": abuse_dict.get('domain', 'N/A'),
            "abuseipdb_hostnames": abuse_dict.get('hostnames', 'N/A'),
            "abuseipdb_isTor": abuse_dict.get('isTor', 'False')
        }

    # Parallelize enrichment
    with ThreadPoolExecutor(max_workers=DEFAULT_WORKERS) as ex:
        futures = {ex.submit(enrich_ip, ip): ip for ip in ip_reasons.keys()}
        for fut in as_completed(futures):
            records.append(fut.result())

    out_path = user_report_dir / f"suspicious_ips_{username}.csv"
    pd.DataFrame(records).to_csv(out_path, index=False)
    write_log(f"Suspicious IPs saved to {out_path}", "Success")


# ----- orchestrator -----
def run_analysis(interactive_path: Path, non_interactive_path: Path, username: str, mode: str, workers: int):
    i_df = safe_read_csv(interactive_path, parse_dates=["Date (UTC)"], dtypes={"IP address": str})
    ni_df = safe_read_csv(non_interactive_path, parse_dates=["Date (UTC)"], dtypes={"IP address": str})
    merged_df = pd.concat([i_df, ni_df], ignore_index=True)

    common_cols = [c for c in i_df.columns if c in ni_df.columns]
    i_df = i_df[common_cols].copy()
    ni_df = ni_df[common_cols].copy()

    all_ips = pd.concat([i_df["IP address"], ni_df["IP address"]], ignore_index=True)
    ip_map = {}
    try:
        reader = geoip2.database.Reader(str(GEOIP_DB))
    except Exception as e:
        write_log(f"GeoIP DB not available at {GEOIP_DB}: {e}. Impossible-travel may be limited.", "Warning")
        reader = None
    if reader:
        ip_map = geoip_lookup_bulk(reader, all_ips.tolist(), workers=workers)
        reader.close()
        resolved = sum(1 for v in ip_map.values() if v)
        total = len(ip_map)
        pct = (resolved / total * 100) if total else 0
        write_log(f"GeoIP resolved {resolved}/{total} unique public IPs ({pct:.1f}%).", "Info")
        if resolved == 0:
            write_log("No IPs resolved. Impossible-travel will not trigger.", "Warning")

    summary = {}
    user_report_dir = REPORT_DIR / username
    user_report_dir.mkdir(parents=True, exist_ok=True)

    # Add timestamp to summary
    summary["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # --- Combined mode ---
    if mode in ("combined", "both"):
        # Run full analysis on merged data (excluding impossible travel for combined data)
        merged_df["date_utc"] = pd.to_datetime(merged_df["Date (UTC)"], utc=True)
        merged_df = prepare_dataframe(merged_df, ip_map)
        combined_detection_functions = ["brute_force", "mfa_spam", "suspicious_devices"]
        combined_summary = run_detection_functions(merged_df, username, "combined", combined_detection_functions)

        # Run impossible travel detection on interactive data only for combined mode
        i_df["date_utc"] = pd.to_datetime(i_df["Date (UTC)"], utc=True)
        i_df_prepared = prepare_dataframe(i_df, ip_map)
        impossible_result = run_detection_functions(i_df_prepared, username, "combined", ["impossible_travel"])
        combined_summary["impossible_count"] = impossible_result["impossible_count"]

        summary["combined"] = combined_summary

    # --- Separate mode ---
    if mode in ("separate", "both"):
        # Interactive - run all detection functions
        i_df["date_utc"] = pd.to_datetime(i_df["Date (UTC)"], utc=True)
        i_df_prepared = prepare_dataframe(i_df, ip_map)
        interactive_detection_functions = ["impossible_travel", "brute_force", "mfa_spam", "suspicious_devices"]
        summary["interactive"] = run_detection_functions(i_df_prepared, username, "interactive", interactive_detection_functions)

        # NonInteractive - run all except impossible travel (too many FP in non-interactive)
        ni_df["date_utc"] = pd.to_datetime(ni_df["Date (UTC)"], utc=True)
        ni_df_prepared = prepare_dataframe(ni_df, ip_map)
        non_interactive_detection_functions = ["brute_force", "mfa_spam", "suspicious_devices"]
        summary["noninteractive"] = run_detection_functions(ni_df_prepared, username, "noninteractive", non_interactive_detection_functions)

    # Save summary.json
    summary_path = user_report_dir / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=4, default=str)
    write_log(f"Summary saved to {summary_path}", "Success")

    # Generate suspicious IPs CSV and integrate results into summary
    generate_suspicious_ips_csv(username)

    # Read the suspicious IPs CSV to extract summary information
    suspicious_ips_path = user_report_dir / f"suspicious_ips_{username}.csv"
    if suspicious_ips_path.exists():
        suspicious_ips_df = pd.read_csv(suspicious_ips_path)

        # Count suspicious IPs
        suspicious_ips_count = len(suspicious_ips_df)

        # Count IPs flagged by VirusTotal
        ips_VT_flagged = 0
        for _, row in suspicious_ips_df.iterrows():
            malicious = int(row.get("virustotal_malicious", 0))
            suspicious = int(row.get("virustotal_suspicious", 0))
            if malicious > 0 or suspicious > 0:
                ips_VT_flagged += 1

        # Count IPs flagged by AbuseIPDB
        ips_abuseipdb_flagged = 0
        for _, row in suspicious_ips_df.iterrows():
            score = int(row.get("abuseipdb_score", 0))
            if score > 0:
                ips_abuseipdb_flagged += 1

        # Create ip_analysis object
        ip_analysis = {
            "suspicious_ips": suspicious_ips_count,
            "ips_VT_flagged": ips_VT_flagged,
            "ips_abuseipdb_flagged": ips_abuseipdb_flagged
        }

        # Add the ip_analysis to the summary
        summary["ip_analysis"] = ip_analysis

        # Update the summary.json file with the new information
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=4, default=str)

    return summary


# ----- CLI -----
def main():
    print("\nSign-In Analysis Tool")
    print("=" * 50)

    parser = argparse.ArgumentParser(
        description="Analyze Microsoft 365 sign-in logs for security anomalies",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-u", "--username", required=False, help="Username to analyze")
    parser.add_argument("--interactive", required=False, help="Path to interactive sign-ins CSV")
    parser.add_argument("--non-interactive", required=False, help="Path to non-interactive sign-ins CSV")
    parser.add_argument("--mode", choices=("combined", "separate", "both"), default=None,
                        help="Analysis mode (if not specified, interactive selection will be shown)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"Number of worker threads (default: {DEFAULT_WORKERS})")
    parser.add_argument("--exports-dir", default=str(EXPORTS_DIR),
                        help=f"Exports directory path (default: {EXPORTS_DIR})")
    parser.add_argument("--list-users", action="store_true",
                        help="Just list available users and exit (fast mode)")
    args = parser.parse_args()

    exports_dir = Path(args.exports_dir)

    # Fast mode: just list users and exit
    if args.list_users:
        print("Fast mode: Listing available users only...")
        available_users = get_available_users(exports_dir)
        if available_users:
            print(f"\nAvailable users ({len(available_users)}):")
            for i, user in enumerate(available_users, 1):
                print(f"{i:2d}. {user}")
        else:
            print("\nNo users with complete export data found.")
        return

    # If no username provided, show interactive selection
    if not args.username:
        available_users = get_available_users(exports_dir)
        if not available_users:
            print("No users with complete export data found in the exports directory.")
            print(f"Please ensure you have both InteractiveSignIns_*.csv and NonInteractiveSignIns_*.csv files in {exports_dir}")
            return

        selected_users = select_users_interactive(available_users)
        if not selected_users:
            print("No users selected. Exiting.")
            return
    else:
        # Single user provided via command line
        selected_users = [args.username.replace("@", "_")]

    # If no mode provided, show interactive selection
    if args.mode is None:
        analysis_mode = select_mode_interactive()
        if analysis_mode is None:
            print("Operation cancelled by user.")
            return
    else:
        analysis_mode = args.mode
        print(f"Using analysis mode: {analysis_mode}")

    # Process each selected user
    for username in selected_users:
        if "@" in username:
            username_safe = username.replace("@", "_")
        else:
            username_safe = username

        print(f"\n{'='*60}")
        print(f"Processing user: {username_safe}")
        print(f"{'='*60}")

        # Look for files in user-specific folder first, then fallback to root exports dir
        user_exports_dir = exports_dir / username_safe

        if args.interactive:
            interactive_path = Path(args.interactive)
        else:
            # Try user-specific folder first
            if user_exports_dir.exists():
                interactive_path = user_exports_dir / f"InteractiveSignIns_{username_safe}.csv"
            else:
                # Fallback to root exports directory
                interactive_path = exports_dir / f"InteractiveSignIns_{username_safe}.csv"

        if args.non_interactive:
            non_interactive_path = Path(args.non_interactive)
        else:
            # Try user-specific folder first
            if user_exports_dir.exists():
                non_interactive_path = user_exports_dir / f"NonInteractiveSignIns_{username_safe}.csv"
            else:
                # Fallback to root exports directory
                non_interactive_path = exports_dir / f"NonInteractiveSignIns_{username_safe}.csv"

        write_log(f"Using files: interactive={interactive_path} non-interactive={non_interactive_path}", "Info")

        if not interactive_path.exists():
            write_log(f"Interactive CSV not found: {interactive_path}", "Error")
            continue
        if not non_interactive_path.exists():
            write_log(f"Non-interactive CSV not found: {non_interactive_path}", "Error")
            continue

        try:
            summary = run_analysis(interactive_path, non_interactive_path, username_safe, analysis_mode, args.workers)
            write_log(f"Summary for {username_safe}: {summary}", "Success")
        except Exception as e:
            write_log(f"Failed to analyze user {username_safe}: {e}", "Error")
            continue

    # Generate HTML report after processing all users
    print(f"\n{'='*60}")
    print("Generating HTML report...")
    print(f"{'='*60}")

    # Pass the same directory arguments to htmlreport.py
    htmlreport_cmd = [
        sys.executable, "htmlreport.py",
        "--reports-dir", str(REPORT_DIR),
        "--exports-dir", str(exports_dir)
    ]
    subprocess.run(htmlreport_cmd)


if __name__ == "__main__":
    main()
