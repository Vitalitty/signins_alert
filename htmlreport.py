import pandas as pd
from pathlib import Path
import json
from datetime import datetime

REPORT_DIR = Path("reports")
OUTPUT_HTML = REPORT_DIR / "all_users_signins_report.html"

EVENT_TYPES = ["impossible_travel", "brute_alerts", "mfa_alerts"]
MODES = ["combined", "interactive", "noninteractive"]

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

def generate_user_data(user_folder: Path):
    username = user_folder.name
    # Get the timestamp from the summary.json file
    summary_path = user_folder / "summary.json"
    timestamp = "Not available"
    creation_date = None  # This will be used for sorting

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
            print(f"Error reading summary for {username}: {e}")
            # If there's an error reading the file, use current time
            creation_date = datetime.now()

    html_parts = [f"<h1>Sign-in Security Report for {username}</h1><p>Generated at {timestamp}</p>"]

    # Read user info file
    user_info_path = Path("Exports") / f"UserInfo_{username.replace('@', '_')}.json"
    last_password_change = "Not available"

    if user_info_path.exists():
        try:
            with open(user_info_path, 'r') as f:
                user_info = json.load(f)
                last_password_change = user_info.get("LastPasswordChangeDate", "Not available")
        except Exception as e:
            print(f"Error reading user info for {username}: {e}")

    # Add user information section
    user_info_html = f"""
    <h2>User Information</h2>
    <table class='summary-table'>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>User Principal Name</td><td>{username}</td></tr>
        <tr><td>Last Password Change</td><td>{last_password_change}</td></tr>
    </table>
    """
    html_parts.append(user_info_html)

    # --- Summary Metrics ---
    summary_html = "<h2>Summary Metrics</h2>"

    # Read summary.json for IP analysis data
    ip_analysis = {}
    if summary_path.exists():
        with open(summary_path, 'r') as f:
            summary_data = json.load(f)
            ip_analysis = summary_data.get("ip_analysis", {})

    # Add IP analysis to summary table
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
                tables_html[event].append((mode, generate_toggle_table(df, f"{event}_{mode}_{username}")))
                ip_col = "ip" if "ip" in df.columns else "IP_clean" if "IP_clean" in df.columns else None
                if ip_col:
                    ip_counts = df[ip_col].value_counts().to_dict()
                    ip_charts_config[event]["datasets"][mode] = ip_counts

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
            # Highlight flagged IPs
            def highlight_flagged(row):
                is_flagged = False

                # Check VirusTotal
                if int(row.get("virustotal_malicious", 0)) > 0 or int(row.get("virustotal_suspicious", 0)) > 0:
                    is_flagged = True

                # Check AbuseIPDB
                if int(row.get("abuseipdb_score", 0)) > 0:
                    is_flagged = True

                return ['background-color: #ffcccc'] * len(row) if is_flagged else [''] * len(row)

            styled_df = suspicious_df.style.apply(highlight_flagged, axis=1)
            html_parts.append("<h3>Suspicious IPs</h3>")
            html_parts.append(generate_toggle_table(styled_df, f"suspicious_ips_{username}"))

    # Add event type tables
    for event, table_list in tables_html.items():
        html_parts.append(f"<h3>{event.replace('_',' ').title()}</h3>")
        for mode, table_html in table_list:
            html_parts.append(f"<h4>Mode: {mode.title()}</h4>")
            html_parts.append(table_html)

    # --- Charts Section ---
    html_parts.append("<h2>Charts</h2>")
    for event in line_charts_config:
        html_parts.append(f"<h3>{event.replace('_',' ').title()}</h3>")
        html_parts.append(f'<h4>Total Events</h4><div class="chart-container"><canvas id="line_{username}_{event}"></canvas></div>')
        html_parts.append(f'<h4>Events by IP</h4><div class="chart-container"><canvas id="ip_{username}_{event}"></canvas></div>')

    return username, "".join(html_parts), line_charts_config, ip_charts_config, creation_date

def generate_toggle_table(df: pd.DataFrame, table_id: str):
    # Check if the DataFrame is a Styler object
    if hasattr(pd, 'Styler') and isinstance(df, pd.Styler):
        html = df.to_html()
    else:
        html = df.to_html(index=False, classes='table', border=0, table_id=table_id)
    return f"""
    <button class="toggle-button" onclick="toggleTable('{table_id}')">Toggle Table</button>
    <div id="{table_id}_container" class="table-container">{html}</div>
    """

def main():
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
                const ctx=document.getElementById('line_'+username+'_'+event).getContext('2d');
                new Chart(ctx,{type:'line',data:{labels:cfg.labels,datasets:[{label:'Total Events',data:cfg.data,fill:false,borderColor:'rgba(75,192,192,1)'}]},options:{responsive:true}});
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
                const ctx=document.getElementById('ip_'+username+'_'+event).getContext('2d');
                new Chart(ctx,{type:'bar',data:{labels:labels,datasets:datasets},options:{responsive:true,scales:{x:{stacked:false},y:{stacked:false}}}});
            });
        }
        function modeColor(mode){
            if(mode==='combined') return 'rgba(54,162,235,0.6)';
            if(mode==='interactive') return 'rgba(255,159,64,0.6)';
            if(mode==='noninteractive') return 'rgba(75,192,192,0.6)';
            return 'rgba(200,200,200,0.6)';
        }
    </script>
    """

    # Collect all user data first
    user_data = []
    for user_folder in REPORT_DIR.iterdir():
        if user_folder.is_dir():
            username, html_content, line_charts_config, ip_charts_config, creation_date = generate_user_data(user_folder)
            user_data.append({
                'username': username,
                'html_content': html_content,
                'line_charts_config': line_charts_config,
                'ip_charts_config': ip_charts_config,
                'creation_date': creation_date
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
        html_content = user['html_content']
        line_charts_config = user['line_charts_config']
        ip_charts_config = user['ip_charts_config']

        active_class = "active" if first else ""
        display_style = "block" if first else "none"
        tabs_html += f'<button class="tablinks {active_class}" onclick="openTab(event, \'{username}\')">{username}</button>'
        tabcontents_html += f'<div id="{username}" class="tabcontent" style="display:{display_style}">{html_content}</div>'
        user_charts_json += f"userChartsData['{username}']={{line_charts:{json.dumps(line_charts_config)},ip_charts:{json.dumps(ip_charts_config)}}};\n"
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

    OUTPUT_HTML.write_text(html_content_full)
    print(f"Combined HTML report generated at {OUTPUT_HTML}")

if __name__ == "__main__":
    main()
