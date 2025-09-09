import pandas as pd
from pathlib import Path
import json
from datetime import datetime
import argparse
import logging
import sys

# ----- Load Configuration -----
CONFIG_FILE = Path("signins_config.json")


def load_config():
    """Load configuration from signins_config.json file."""
    # Define default configuration structure
    default_config = {
        "directories": {
            "reports_dir": "reports",
            "exports_dir": "exports"
        },
        "html_report": {
            "output_filename": "all_users_signins_report.html"
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

# Default directories (can be overridden by command line arguments or config file)
DEFAULT_REPORT_DIR = Path(config["directories"]["reports_dir"])
DEFAULT_EXPORTS_DIR = Path(config["directories"]["exports_dir"])

# Core program constants - these define what the script can process
EVENT_TYPES = ["impossible_travel", "brute_alerts", "mfa_alerts", "suspicious_devices"]
MODES = ["combined", "interactive", "noninteractive"]
OUTPUT_FILENAME = config["html_report"]["output_filename"]


# ----- Logging -----
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

# ----- Log Configuration Summary -----
write_log(f"Using configuration: reports_dir='{DEFAULT_REPORT_DIR}', exports_dir='{DEFAULT_EXPORTS_DIR}', "
          + f"output_filename='{OUTPUT_FILENAME}', log_level='{config['logging']['level']}', "
          + f"colors_enabled={config['logging']['colors_enabled']}", "Info")


def read_csv_safe(path: Path):
    if not path.exists():
        return pd.DataFrame()
    try:
        df = pd.read_csv(path)
        if df.empty:
            return pd.DataFrame()
        return df
    except pd.errors.EmptyDataError:
        return pd.DataFrame()


def generate_user_data(user_folder: Path, exports_dir: Path):
    username = user_folder.name
    summary_path = user_folder / "summary.json"
    timestamp = "Not available"
    creation_date = None

    if summary_path.exists():
        try:
            with open(summary_path, 'r') as f:
                summary_data = json.load(f)
                # Get the timestamp from the summary file
                timestamp = summary_data.get("timestamp", "Not available")
                # Parse the timestamp to a datetime object for sorting
                try:
                    creation_date = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S %Z")
                except (ValueError, TypeError):
                    # Fallback if parsing fails - use current time as a last resort
                    creation_date = datetime.now()
        except Exception as e:
            write_log(f"Error reading summary for {username}: {e}", "Error")
            # If there's an error reading the file, use current time
            creation_date = datetime.now()

    # First try the user-specific folder in exports for user information
    user_specific_exports = exports_dir / username / f"UserInfo_{username}.json"
    last_password_change = "Not available"
    real_email = username  # Fallback to sanitized username if real email not found

    if user_specific_exports.exists():
        try:
            with open(user_specific_exports, 'r', encoding='utf-8') as f:
                user_info = json.load(f)
                raw_last_password_change = user_info.get("LastPasswordChangeDate", None)
                UserUPN = user_info.get("UPN", "Not available")
                real_email = UserUPN if UserUPN != "Not available" else username  # Use real email if available
                City = user_info.get("City", "Not available")
                State = user_info.get("State", "Not available")
                Country = user_info.get("Country", "Not available")
                Department = user_info.get("Department", "Not available")
                OfficeLocation = user_info.get("OfficeLocation", "Not available")
                if raw_last_password_change is not None:
                    try:
                        # Convert from milliseconds to seconds, then format
                        dt = datetime.fromtimestamp(int(raw_last_password_change) / 1000)
                        last_password_change = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        last_password_change = str(raw_last_password_change)
                else:
                    last_password_change = "Not available"
        except Exception as e:
            write_log(f"Error reading user info for {username}: {e}", "Error")
            UserUPN = "Not available"

    html_parts = [f"<h1>Sign-in Security Report for {real_email}</h1><p>Generated at {timestamp}</p>"]

    # Add user information section
    user_info_html = f"""
    <h2>User Information</h2>
    <table class='summary-table'>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>User Principal Name</td><td>{UserUPN}</td></tr>
        <tr><td>Last Password Change</td><td>{last_password_change}</td></tr>
        <tr><td>City</td><td>{City}</td></tr>
        <tr><td>State</td><td>{State}</td></tr>
        <tr><td>Country</td><td>{Country}</td></tr>
        <tr><td>Department</td><td>{Department}</td></tr>
        <tr><td>Office Location</td><td>{OfficeLocation}</td></tr>
    </table>
    """
    html_parts.append(user_info_html)

    devices_specific_exports = exports_dir / username / f"DevicesInfo_{username}.json"

    if devices_specific_exports.exists():
        try:
            with open(devices_specific_exports, 'r', encoding='utf-8') as f:
                device_data = json.load(f)
                devices = device_data.get("Devices", [])

                if devices:
                    # Create devices section header
                    devices_info_html = "<h2>Device Information</h2>"

                    # Create a single table with all devices
                    devices_info_html += """
                    <table class='summary-table'>
                    <tr>
                        <th>Device ID</th>
                        <th>Registration Date</th>
                        <th>Display Name</th>
                        <th>Device Ownership</th>
                        <th>Manufacturer</th>
                        <th>Model</th>
                        <th>Operating System</th>
                        <th>Trust Type</th>
                        <th>Enrollment Type</th>
                    </tr>
                    """

                    for device in devices:
                        deviceId = device.get("DeviceId", "Not available")
                        registrationDateTimeunixMs = device.get("RegistrationDateTime", "Not available")
                        displayName = device.get("DisplayName", "Not available")
                        deviceOwnership = device.get("DeviceOwnership", "Not available")
                        manufacturer = device.get("Manufacturer", "Not available")
                        model = device.get("Model", "Not available")
                        operatingSystem = device.get("OperatingSystem", "Not available")
                        trustType = device.get("TrustType", "Not available")
                        enrollmentType = device.get("EnrollmentType", "Not available")

                        if registrationDateTimeunixMs != "Not available" and registrationDateTimeunixMs is not None:
                            try:
                                # Convert from milliseconds to seconds, then format
                                dt = datetime.fromtimestamp(int(registrationDateTimeunixMs) / 1000)
                                registration_date_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                            except Exception:
                                registration_date_time = str(registrationDateTimeunixMs)
                        else:
                            registration_date_time = "Not available"

                        # Add device row to table
                        devices_info_html += f"""
                        <tr>
                            <td>{deviceId}</td>
                            <td>{registration_date_time}</td>
                            <td>{displayName}</td>
                            <td>{deviceOwnership}</td>
                            <td>{manufacturer}</td>
                            <td>{model}</td>
                            <td>{operatingSystem}</td>
                            <td>{trustType}</td>
                            <td>{enrollmentType}</td>
                        </tr>
                        """

                    devices_info_html += "</table>"
                    html_parts.append(devices_info_html)

        except Exception as e:
            write_log(f"Error reading device info for {username}: {e}", "Error")

    # --- Summary Metrics ---
    summary_html = "<h2>Summary Metrics</h2>"

    # Read summary.json for IP analysis data
    ip_analysis = {}
    if summary_path.exists():
        with open(summary_path, 'r') as f:
            summary_data = json.load(f)
            ip_analysis = summary_data.get("ip_analysis", {})

    # Add IP analysis to summary table
    if ip_analysis:
        summary_html += "<table class='summary-table'>"
        summary_html += "<tr><th>IP Analysis</th><th>Number</th></tr>"
        summary_html += f"<tr><td>Suspicious IPs</td><td>{ip_analysis.get('suspicious_ips', 0)}</td></tr>"
        summary_html += f"<tr><td>IPs Flagged by VirusTotal</td><td>{ip_analysis.get('ips_VT_flagged', 0)}</td></tr>"
        summary_html += f"<tr><td>IPs Flagged by AbuseIPDB</td><td>{ip_analysis.get('ips_abuseipdb_flagged', 0)}</td></tr>"
        summary_html += "</table>"

    # Add event type summary
    summary_html += "<table class='summary-table'><tr><th>Event Type</th><th>Mode</th><th>Total Events</th></tr>"

    tables_html = {}
    line_charts_config = {}
    ip_charts_config = {}

    # Use refactored aggregation
    event_mode_counts, ip_labels = aggregate_event_mode_counts(user_folder, username)

    for event in EVENT_TYPES:
        event_has_data = False
        tables_html[event] = []
        line_charts_config[event] = {"labels": MODES, "data": []}
        ip_charts_config[event] = {"datasets": {mode: {} for mode in MODES}}

        for mode in MODES:
            file_path = user_folder / f"{event}_{username}_{mode}.csv"
            df = read_csv_safe(file_path)
            count = len(df)
            line_charts_config[event]["data"].append(count)
            if count > 0:
                event_has_data = True
                tables_html[event].append((mode, generate_toggle_table(df, f"{event}_{mode}_{username}", mode)))
                # Use refactored aggregation for ip_charts_config
                ip_charts_config[event]["datasets"][mode] = event_mode_counts[event][mode]
            summary_html += f"<tr><td>{event.replace('_',' ').title()}</td><td>{mode.title()}</td><td>{count}</td></tr>"
        if not event_has_data:
            line_charts_config.pop(event)
            ip_charts_config.pop(event)
            tables_html.pop(event)
    summary_html += "</table>"
    html_parts.append(summary_html)

    # --- Tables Section ---
    html_parts.append("<h2>Tables</h2>")

    # Add suspicious IPs table if it exists
    suspicious_ips_path = user_folder / f"suspicious_ips_{username}.csv"
    if suspicious_ips_path.exists():
        suspicious_df = read_csv_safe(suspicious_ips_path)
        if not suspicious_df.empty:
            # Highlight flagged IPs with different colors based on threat level
            def highlight_flagged(row):
                vt_malicious = int(row.get("virustotal_malicious", 0))
                vt_suspicious = int(row.get("virustotal_suspicious", 0))
                abuseipdb_score = int(row.get("abuseipdb_score", 0))

                # Red highlighting (high threat)
                if vt_malicious >= 3 or abuseipdb_score >= 33:
                    return ['background-color: #ffcccc'] * len(row)

                # Yellow highlighting (medium threat)
                elif vt_suspicious > 0 or (0 < vt_malicious < 3) or (0 < abuseipdb_score < 33):
                    return ['background-color: #fff2cc'] * len(row)

                # No highlighting (no threat indicators)
                else:
                    return [''] * len(row)

            styled_df = suspicious_df.style.apply(highlight_flagged, axis=1)
            html_parts.append("<h3>Suspicious IPs</h3>")
            # For Suspicious IPs, don't include mode in the button name
            html_parts.append(generate_toggle_table(styled_df, f"suspicious_ips_{username}", None))

    # Add event type tables
    for event, table_list in tables_html.items():
        html_parts.append(f"<h3>{event.replace('_',' ').title()}</h3>")
        for mode, table_html in table_list:
            html_parts.append(table_html)

    # --- Charts Section ---
    html_parts.append("<h2>Charts</h2>")
    # Use refactored aggregation for event type chart
    event_colors = {
        "impossible_travel": "rgba(54,162,235,0.7)",
        "brute_alerts": "rgba(75,192,192,0.7)",
        "mfa_alerts": "rgba(255,206,86,0.7)",
        "suspicious_devices": "rgba(255,99,132,0.7)"
    }
    datasets = []
    for event in EVENT_TYPES:
        data = [sum(event_mode_counts[event][mode].get(ip, 0) for mode in MODES) for ip in ip_labels]
        datasets.append({
            "label": event.replace('_', ' ').title(),
            "data": data,
            "backgroundColor": event_colors.get(event, "rgba(200,200,200,0.7)")
        })
    if ip_labels:
        html_parts.append(f'<h3>Total Events per IP (by Event Type)</h3><div class="chart-container"><canvas id="total_events_per_ip_{username}"></canvas></div>')
    for event in line_charts_config:
        html_parts.append(f"<h3>{event.replace('_',' ').title()}</h3>")
        html_parts.append(f'<h4>Total Events</h4><div class="chart-container"><canvas id="line_{username}_{event}"></canvas></div>')
        html_parts.append(f'<h4>Events by IP</h4><div class="chart-container"><canvas id="ip_{username}_{event}"></canvas></div>')
    return username, real_email, "".join(html_parts), line_charts_config, ip_charts_config, creation_date, ip_labels, datasets


def aggregate_event_mode_counts(user_folder, username):
    """Aggregate event counts by event type, mode, and IP for a user."""
    event_mode_counts = {event: {mode: {} for mode in MODES} for event in EVENT_TYPES}
    all_ip_set = set()
    for event in EVENT_TYPES:
        for mode in MODES:
            file_path = user_folder / f"{event}_{username}_{mode}.csv"
            df = read_csv_safe(file_path)
            if not df.empty and "ip" in df.columns:
                for ip, count in df["ip"].value_counts().items():
                    ip_str = str(ip)
                    event_mode_counts[event][mode][ip_str] = count
                    all_ip_set.add(ip_str)
    return event_mode_counts, sorted(all_ip_set)


def generate_toggle_table(df: pd.DataFrame, table_id: str, mode: str = None):
    # Check if the DataFrame is a Styler object
    if hasattr(pd, 'Styler') and isinstance(df, pd.Styler):
        html = df.to_html()
    else:
        html = df.to_html(index=False, classes='table', border=0, table_id=table_id)

    # Create button text based on whether mode is provided
    button_text = "Toggle Table"
    if mode is not None:
        button_text = f"Toggle Table ({mode.title()})"

    return f"""
    <button class=\"toggle-button\" onclick=\"toggleTable('{table_id}')\">{button_text}</button>
    <div id=\"{table_id}_container\" class=\"table-container\" style=\"display:none;\">{html}</div>
    """


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Generate HTML report from sign-in analysis results",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--reports-dir", default=str(DEFAULT_REPORT_DIR),
                        help=f"Reports directory path (default: {DEFAULT_REPORT_DIR})")
    parser.add_argument("--exports-dir", default=str(DEFAULT_EXPORTS_DIR),
                        help=f"Exports directory path (default: {DEFAULT_EXPORTS_DIR})")

    args = parser.parse_args()

    # Convert arguments to Path objects
    report_dir = Path(args.reports_dir)
    exports_dir = Path(args.exports_dir)
    output_html = report_dir / OUTPUT_FILENAME

    # Validate directories exist
    if not report_dir.exists():
        write_log(f"Error: Reports directory not found: {report_dir}", "Error")
        write_log("Please run analyse.py first to generate reports, or specify correct --reports-dir", "Error")
        sys.exit(1)

    css_js = """
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2C3E50; }
        h2 { color: #34495E; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        h3 { color: #555; margin-top:20px; }
        h4 { color: #666; margin-left:10px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        tr:nth-child(even){background-color: #f2f2f2;}
        th { background-color: #4CAF50; color: white; }
        .toggle-button { margin-bottom:5px; padding:5px 10px; cursor:pointer; }
        .table-container { display:none; margin-bottom:15px; }
        .summary-table th { background-color:#555; color:white; }
        .chart-container { width:100%; max-width:800px; margin-bottom:30px; }
        .tab { overflow: hidden; border-bottom: 1px solid #ccc; }
        .tab button { background-color: inherit; border: none; outline: none; cursor: pointer; padding: 10px 15px; transition: 0.3s; }
        .tab button:hover { background-color: #ddd; }
        .tab button.active { background-color: #ccc; }
        .tabcontent { display: none; padding: 10px 0; }
        .user-info-table { margin-bottom: 20px; }
        .user-info-table th { width: 200px; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        const userChartsData = {};
        // Store chart instances by canvas id
        const chartInstances = {};
        function toggleTable(id){
            const c = document.getElementById(id+"_container");
            c.style.display = c.style.display==="none"?"block":"none";
        }
        function openTab(evt, username){
            const tabs=document.getElementsByClassName("tabcontent");
            for(let t of tabs)t.style.display="none";
            const tablinks=document.getElementsByClassName("tablinks");
            for(let l of tablinks) l.className=l.className.replace(" active","");
            document.getElementById(username).style.display="block";
            evt.currentTarget.className+=" active";
            drawCharts(username);
        }
        function drawCharts(username){
            const data = userChartsData[username];
            if(!data) return;
            Object.keys(data.line_charts).forEach(event=>{
                const cfg=data.line_charts[event];
                const canvasId = 'line_'+username+'_'+event;
                const ctx=document.getElementById(canvasId).getContext('2d');
                // Destroy previous chart if exists
                if(chartInstances[canvasId]){
                    chartInstances[canvasId].destroy();
                }
                chartInstances[canvasId] = new Chart(ctx,{type:'line',data:{labels:cfg.labels,datasets:[{label:'Total Events',data:cfg.data,fill:false,borderColor:'rgba(75,192,192,1)'}]},options:{responsive:true}});
            });
            Object.keys(data.ip_charts).forEach(event=>{
                const all_ips = new Set();
                Object.values(data.ip_charts[event].datasets).forEach(dset=>Object.keys(dset).forEach(ip=>all_ips.add(ip)));
                const labels = Array.from(all_ips);
                const datasets=[];
                Object.keys(data.ip_charts[event].datasets).forEach(mode=>{
                    const values=labels.map(ip=>data.ip_charts[event].datasets[mode][ip]||0);
                    datasets.push({label:mode,data:values,backgroundColor:modeColor(mode)});
                });
                const canvasId = 'ip_'+username+'_'+event;
                const ctx=document.getElementById(canvasId).getContext('2d');
                // Destroy previous chart if exists
                if(chartInstances[canvasId]){
                    chartInstances[canvasId].destroy();
                }
                chartInstances[canvasId] = new Chart(ctx,{type:'bar',data:{labels:labels,datasets:datasets},options:{responsive:true,scales:{x:{stacked:false},y:{stacked:false}}}});
            });
            // Destroy previous chart if exists
            const totalIpCanvasId = 'total_events_per_ip_'+username;
            const totalIpCanvas = document.getElementById(totalIpCanvasId);
            if(totalIpCanvas){
                if(chartInstances[totalIpCanvasId]){
                    chartInstances[totalIpCanvasId].destroy();
                }
                chartInstances[totalIpCanvasId] = new Chart(totalIpCanvas.getContext('2d'),{
                    type:'bar',
                    data:{labels:userChartsData[username]["total_events_per_ip"].labels,datasets:userChartsData[username]["total_events_per_ip"].datasets},
                    options:{responsive:true,scales:{x:{stacked:true},y:{stacked:true}}}
                });
            }
        }
        function modeColor(mode){
            if(mode==='combined') return 'rgba(54,162,235,0.6)';
            if(mode==='interactive') return 'rgba(255,159,64,0.6)';
            if(mode==='noninteractive') return 'rgba(75,192,192,0.6)';
            return 'rgba(200,200,200,0.6)';
        }
    </script>
    """

    # Collect all user data
    user_data = []
    for user_folder in report_dir.iterdir():
        if user_folder.is_dir():
            username, real_email, html_content, line_charts_config, ip_charts_config, creation_date, ip_labels, datasets = generate_user_data(user_folder, exports_dir)
            user_data.append({
                'username': username,
                'real_email': real_email,
                'html_content': html_content,
                'line_charts_config': line_charts_config,
                'ip_charts_config': ip_charts_config,
                'creation_date': creation_date,
                'ip_labels': ip_labels,
                'datasets': datasets
            })

    # Sort users by creation date (oldest first)
    user_data.sort(key=lambda x: x['creation_date'])

    # Generate tabs and content in chronological order
    tabs_html = '<div class="tab">'
    tabcontents_html = ''
    first = True
    user_charts_json = ""

    for user in user_data:
        username = user['username']
        real_email = user['real_email']
        html_content = user['html_content']
        line_charts_config = user['line_charts_config']
        ip_charts_config = user['ip_charts_config']
        ip_labels = user.get('ip_labels', [])
        datasets = user.get('datasets', [])

        active_class = "active" if first else ""
        display_style = "block" if first else "none"
        tabs_html += f'<button class="tablinks {active_class}" onclick="openTab(event, \'{username}\')">{real_email}</button>'
        tabcontents_html += f'<div id="{username}" class="tabcontent" style="display:{display_style}">{html_content}</div>'
        user_charts_json += f"userChartsData['{username}']={{line_charts:{json.dumps(line_charts_config)},ip_charts:{json.dumps(ip_charts_config)},total_events_per_ip:{{labels:{json.dumps(ip_labels)},datasets:{json.dumps(datasets)}}}}};\n"
        first = False

    tabs_html += '</div>'

    html_content_full = f"""
    <!DOCTYPE html>
    <html>
    <head>{css_js}</head>
    <body>
    {tabs_html}
    {tabcontents_html}
    <script>
    {user_charts_json}
    const firstUser=Object.keys(userChartsData)[0];
    if(firstUser) drawCharts(firstUser);
    </script>
    </body>
    </html>
    """

    output_html.write_text(html_content_full)
    write_log(f"Combined HTML report generated at {output_html}", "Success")

    # Also print directory information for user reference
    write_log("Report generated from:", "Info")
    write_log(f"  Reports directory: {report_dir}", "Info")
    write_log(f"  Exports directory: {exports_dir}", "Info")


if __name__ == "__main__":
    main()
