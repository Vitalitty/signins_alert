from pathlib import Path
import argparse
import logging
import pandas as pd
import numpy as np
import geoip2.database
import ipaddress
from geoip2.errors import AddressNotFoundError
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import subprocess
import sys
from dotenv import load_dotenv
import os
import requests
from datetime import datetime, timezone

# ----- config -----
MIN_TIME_SECONDS = 1  # avoid divisions by very small delta
THRESHOLD_KMH = 900
BRUTE_WINDOW = pd.Timedelta(minutes=1)
BRUTE_MIN_ATTEMPTS = 3
MFA_WINDOW = pd.Timedelta(minutes=1)
MFA_MIN_ATTEMPTS = 3
GEOIP_DB = Path("GeoDB/GeoLite2-City.mmdb")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)
DEFAULT_WORKERS = 8
EXPORTS_DIR = Path("Exports")

# ----- logging -----
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ----- Load API keys -----
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

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
    return pd.read_csv(path, **kwargs)

def haversine_vec(lat1, lon1, lat2, lon2):
    """Returns distance in km between arrays/values (numpy arrays supported)."""
    lat1, lon1, lat2, lon2 = map(np.radians, (lat1, lon1, lat2, lon2))
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = np.sin(dlat/2.0)**2 + np.cos(lat1)*np.cos(lat2)*np.sin(dlon/2.0)**2
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
        resp = requests.get(url, headers=headers, timeout=10)
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
        resp = requests.get(url, headers=headers, params=params, timeout=10)
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

# ----- core analysis -----
def analyze_df(df: pd.DataFrame, username: str, ip_map: dict, suffix: str, compute_impossible: bool, compute_brute_mfa: bool):
    logging.info("Analysis (%s): %d events", suffix, len(df))

    # Ensure per-user report folder exists
    user_report_dir = REPORT_DIR / username
    user_report_dir.mkdir(parents=True, exist_ok=True)

    df["IP_clean"] = df.get("IP address", pd.Series([None] * len(df))).apply(lambda x: str(x).strip() if pd.notna(x) and str(x).strip() != "" else None)
    df["Coordinates"] = df["IP_clean"].map(ip_map)
    df["lat"] = df["Coordinates"].apply(lambda x: x[0] if isinstance(x, (list, tuple)) and len(x) > 0 else np.nan)
    df["lon"] = df["Coordinates"].apply(lambda x: x[1] if isinstance(x, (list, tuple)) and len(x) > 1 else np.nan)

    df = df.sort_values("Date (UTC)").reset_index(drop=True)
    df["prev_time"] = df["Date (UTC)"].shift(1)
    df["prev_lat"] = df["lat"].shift(1)
    df["prev_lon"] = df["lon"].shift(1)

    impossible_count = 0
    brute_count = 0
    mfa_count = 0

    if compute_impossible:
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
        df["time_diff_s"] = (df["Date (UTC)"] - df["prev_time"]).dt.total_seconds()
        df.loc[df["time_diff_s"].abs() < MIN_TIME_SECONDS, "time_diff_s"] = np.nan
        df["time_diff_h"] = df["time_diff_s"] / 3600.0
        df["speed_kmh"] = df["distance_km"] / df["time_diff_h"]

        # Clean up invalid divisions (NaN, inf from division by zero)
        df["speed_kmh"] = df["speed_kmh"].replace([np.inf, -np.inf], np.nan)
        df["speed_kmh"] = df["speed_kmh"].fillna(0)

        impossible = df[df["speed_kmh"] > THRESHOLD_KMH].copy()
        impossible_count = len(impossible)
        logging.info("[%s] Impossible travel anomalies: %d", suffix, impossible_count)
        if impossible_count > 0:
            impossible.to_csv(user_report_dir / f"impossible_travel_{username}_{suffix}.csv", index=False)

    if compute_brute_mfa:
        df["Status"] = df.get("Status", pd.Series([""] * len(df))).fillna("").astype(str)
        if "Sign-in error code" in df.columns:
            df["Sign-in error code"] = pd.to_numeric(df["Sign-in error code"], errors="coerce").fillna(0).astype(int)

        # Brute-force
        failures = df[(df["Status"] != "Success") | (df.get("Sign-in error code", 0) != 0)].copy()
        brute_alerts = []
        for ip, group in failures.groupby("IP_clean"):
            times = group["Date (UTC)"].dropna().tolist()
            alerts = sliding_window_alerts(times, BRUTE_MIN_ATTEMPTS, BRUTE_WINDOW)
            for a, b, c in alerts:
                brute_alerts.append({"ip": ip, "start": a, "end": b, "count": c, "type": "brute-force"})
        brute_count = len(brute_alerts)
        logging.info("[%s] Brute-force alerts: %d", suffix, brute_count)
        if brute_alerts:
            pd.DataFrame(brute_alerts).to_csv(user_report_dir / f"brute_alerts_{username}_{suffix}.csv", index=False)

        # MFA
        mfa_col = "Multifactor authentication result"
        mfa_alerts = []
        if mfa_col in df.columns:
            mfa_fail = df[df[mfa_col].isin(["interrupted", "failure", "challenge"])].copy()
            for ip, group in mfa_fail.groupby("IP_clean"):
                times = group["Date (UTC)"].dropna().tolist()
                alerts = sliding_window_alerts(times, MFA_MIN_ATTEMPTS, MFA_WINDOW)
                for a, b, c in alerts:
                    mfa_alerts.append({"ip": ip, "start": a, "end": b, "count": c, "type": "mfa-spam"})
        mfa_count = len(mfa_alerts)
        logging.info("[%s] MFA alerts: %d", suffix, mfa_count)
        if mfa_alerts:
            pd.DataFrame(mfa_alerts).to_csv(user_report_dir / f"mfa_alerts_{username}_{suffix}.csv", index=False)

    return {
        "events": len(df),
        "impossible_count": impossible_count,
        "brute_count": brute_count,
        "mfa_count": mfa_count
    }

# ----- Suspicious IP CSV -----
def generate_suspicious_ips_csv(username):
    user_report_dir = REPORT_DIR / username
    alert_files = list(user_report_dir.glob("*.csv"))

    # Collect unique IPs and reasons
    ip_reasons = {}
    for f in alert_files:
        df = pd.read_csv(f)
        reason = None
        if "speed_kmh" in df.columns:
            reason = "impossible-travel"
            ip_col = "IP_clean"
        elif "type" in df.columns:
            ip_col = "ip"
            reason = None
        else:
            continue

        for idx, row in df.iterrows():
            ip = row[ip_col]
            if pd.isna(ip) or str(ip).strip()=="":
                continue
            ip = str(ip).strip()
            alert_type = row.get("type", reason)
            if ip not in ip_reasons:
                ip_reasons[ip] = set()
            ip_reasons[ip].add(alert_type)

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
    logging.info("Suspicious IPs saved to %s", out_path)

# ----- orchestrator -----
def run_analysis(interactive_path: Path, non_interactive_path: Path, username: str, mode: str, workers: int):
    i_df = safe_read_csv(interactive_path, parse_dates=["Date (UTC)"], dtypes={"IP address": str})
    ni_df = safe_read_csv(non_interactive_path, parse_dates=["Date (UTC)"], dtypes={"IP address": str})

    common_cols = [c for c in i_df.columns if c in ni_df.columns]
    i_df = i_df[common_cols].copy()
    ni_df = ni_df[common_cols].copy()

    all_ips = pd.concat([i_df["IP address"], ni_df["IP address"]], ignore_index=True)
    ip_map = {}
    try:
        reader = geoip2.database.Reader(str(GEOIP_DB))
    except Exception as e:
        logging.warning("GeoIP DB not available at %s: %s. Impossible-travel may be limited.", GEOIP_DB, e)
        reader = None
    if reader:
        ip_map = geoip_lookup_bulk(reader, all_ips.tolist(), workers=workers)
        reader.close()
        resolved = sum(1 for v in ip_map.values() if v)
        total = len(ip_map)
        pct = (resolved / total * 100) if total else 0
        logging.info("GeoIP resolved %d/%d unique public IPs (%.1f%%).", resolved, total, pct)
        if resolved == 0:
            logging.warning("No IPs resolved. Impossible-travel will not trigger.")

    summary = {}
    user_report_dir = REPORT_DIR / username
    user_report_dir.mkdir(parents=True, exist_ok=True)

    # Add timestamp to summary
    summary["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # --- Combined mode ---
    if mode in ("combined", "both"):
        # Impossible Travel on interactive only
        i_df["Date (UTC)"] = pd.to_datetime(i_df["Date (UTC)"], utc=True)
        i_df = i_df.sort_values("Date (UTC)").reset_index(drop=True)
        imp_summary = analyze_df(i_df, username, ip_map, suffix="interactive", compute_impossible=True, compute_brute_mfa=False)
        # Also save impossible CSV for combined
        if imp_summary["impossible_count"] > 0:
            pd.read_csv(user_report_dir / f"impossible_travel_{username}_interactive.csv").to_csv(
                user_report_dir / f"impossible_travel_{username}_combined.csv", index=False
            )

        # Brute + MFA on merged CSV
        merged_df = pd.concat([i_df, ni_df], ignore_index=True)
        merged_df["Date (UTC)"] = pd.to_datetime(merged_df["Date (UTC)"], utc=True)
        merged_df = merged_df.sort_values("Date (UTC)").reset_index(drop=True)
        brute_mfa_summary = analyze_df(merged_df, username, ip_map, suffix="combined", compute_impossible=False, compute_brute_mfa=True)

        # Merge results
        brute_mfa_summary["impossible_count"] = imp_summary["impossible_count"]
        summary["combined"] = brute_mfa_summary

    # --- Separate mode ---
    if mode in ("separate", "both"):
        # Interactive
        i_df["Date (UTC)"] = pd.to_datetime(i_df["Date (UTC)"], utc=True)
        i_df = i_df.sort_values("Date (UTC)").reset_index(drop=True)
        summary["interactive"] = analyze_df(i_df, username, ip_map, suffix="interactive", compute_impossible=True, compute_brute_mfa=True)

        # NonInteractive
        ni_df["Date (UTC)"] = pd.to_datetime(ni_df["Date (UTC)"], utc=True)
        ni_df = ni_df.sort_values("Date (UTC)").reset_index(drop=True)
        summary["noninteractive"] = analyze_df(ni_df, username, ip_map, suffix="noninteractive", compute_impossible=False, compute_brute_mfa=True)

    # Save summary.json
    summary_path = user_report_dir / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=4, default=str)
    logging.info("Summary saved to %s", summary_path)

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
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("--interactive", required=False)
    parser.add_argument("--non-interactive", required=False)
    parser.add_argument("--mode", choices=("combined","separate","both"), default="combined")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--exports-dir", default=str(EXPORTS_DIR))
    args = parser.parse_args()

    username = args.username
    username_safe = username.replace("@", "_")
    exports_dir = Path(args.exports_dir)

    if args.interactive:
        interactive_path = Path(args.interactive)
    else:
        interactive_path = exports_dir / f"InteractiveSignIns_{username_safe}.csv"
    if args.non_interactive:
        non_interactive_path = Path(args.non_interactive)
    else:
        non_interactive_path = exports_dir / f"NonInteractiveSignIns_{username_safe}.csv"

    logging.info("Using files: interactive=%s non-interactive=%s", interactive_path, non_interactive_path)

    if not interactive_path.exists():
        raise FileNotFoundError(f"Interactive CSV not found: {interactive_path}")
    if not non_interactive_path.exists():
        raise FileNotFoundError(f"Non-interactive CSV not found: {non_interactive_path}")

    summary = run_analysis(interactive_path, non_interactive_path, username_safe, args.mode, args.workers)
    logging.info("Summary: %s", summary)

    subprocess.run([sys.executable, "htmlreport.py"])

if __name__ == "__main__":
    main()
