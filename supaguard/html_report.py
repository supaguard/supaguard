"""
SupaGuard Interactive HTML Security Report Generator
Generates single-file dark-mode security scorecards.
"""

from datetime import datetime
from pathlib import Path

def generate_html_report(target_path: str, findings: list, files_scanned: int, elapsed_time: float, output_file: Path):
    crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")

    if crit_count > 0:
        grade = "F"
        grade_color = "#ef4444"
    elif high_count > 2:
        grade = "D"
        grade_color = "#f97316"
    elif high_count > 0 or med_count > 3:
        grade = "C"
        grade_color = "#eab308"
    elif med_count > 0 or low_count > 2:
        grade = "B"
        grade_color = "#3b82f6"
    else:
        grade = "A+"
        grade_color = "#10b981"

    findings_rows = ""
    for idx, f in enumerate(findings, 1):
        sev = f.get("severity", "LOW")
        sev_badge_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6"
        }.get(sev, "#6b7280")

        snippet_html = f"<pre><code>{f.get('snippet', '')}</code></pre>" if f.get("snippet") else "<span style='color:#6b7280'>N/A</span>"

        findings_rows += f"""
        <tr>
            <td>#{idx}</td>
            <td><span class="badge" style="background:{sev_badge_color}">{sev}</span></td>
            <td><strong>{f.get('name', f.get('title', 'Security Finding'))}</strong><br><small style="color:#9ca3af">{f.get('desc', f.get('detail', ''))}</small></td>
            <td><code>{f.get('file', '')}:{f.get('line', 1)}</code></td>
            <td><span class="engine-badge">{f.get('engine', 'SupaGuard')}</span></td>
            <td>{snippet_html}</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SupaGuard Security Report - {Path(target_path).name}</title>
    <style>
        :root {{
            --bg-main: #0c0a1d;
            --bg-card: #181433;
            --border: #2e285e;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #818cf8;
            --lightning: #60a5fa;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg-main);
            color: var(--text-main);
            margin: 0;
            padding: 30px 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        h1 {{ margin: 0; font-size: 24px; color: #ffffff; letter-spacing: -0.5px; }}
        .tagline {{ font-size: 11px; color: var(--lightning); font-weight: 700; text-transform: uppercase; letter-spacing: 1px; }}
        .header-meta {{ color: var(--text-muted); font-size: 13px; margin-top: 4px; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .card-value {{
            font-size: 32px;
            font-weight: bold;
            margin-top: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
        }}
        th, td {{
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            font-size: 14px;
        }}
        th {{
            background: #110d28;
            color: var(--text-muted);
            font-weight: 600;
        }}
        tr:hover {{ background: #201a42; }}
        .badge {{
            padding: 4px 8px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 11px;
            color: white;
        }}
        .engine-badge {{
            background: #2e285e;
            padding: 3px 6px;
            border-radius: 4px;
            font-size: 12px;
            color: #cbd5e1;
        }}
        pre {{
            margin: 0;
            background: #070514;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            max-width: 320px;
            overflow-x: auto;
            color: #fca5a5;
        }}
        .clean-state {{
            padding: 50px;
            text-align: center;
            background: var(--bg-card);
            border-radius: 12px;
            border: 1px solid #10b981;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div>
                    <h1>SUPAGUARD</h1>
                    <div class="tagline">100% Security Suite</div>
                    <div class="header-meta">Target: <strong>{target_path}</strong> • {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
                </div>
            </div>
            <div style="text-align: right;">
                <span style="font-size: 12px; color: var(--text-muted)">Security Score</span>
                <div style="font-size: 36px; font-weight: 900; color: {grade_color}">{grade}</div>
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <div style="color: var(--text-muted)">Files Scanned</div>
                <div class="card-value">{files_scanned}</div>
            </div>
            <div class="card">
                <div style="color: var(--text-muted)">Scan Time</div>
                <div class="card-value">{elapsed_time:.2f}s</div>
            </div>
            <div class="card">
                <div style="color: var(--text-muted)">Critical Threats</div>
                <div class="card-value" style="color:#ef4444">{crit_count}</div>
            </div>
            <div class="card">
                <div style="color: var(--text-muted)">High Severity</div>
                <div class="card-value" style="color:#f97316">{high_count}</div>
            </div>
            <div class="card">
                <div style="color: var(--text-muted)">Medium / Low</div>
                <div class="card-value" style="color:#eab308">{med_count + low_count}</div>
            </div>
        </div>

        {"<table><thead><tr><th>#</th><th>Severity</th><th>Threat / Vulnerability</th><th>Location</th><th>Engine</th><th>Snippet</th></tr></thead><tbody>" + findings_rows + "</tbody></table>" if findings else "<div class='clean-state'><h2 style='color:#10b981; margin:0;'>CLEAN REPOSITORY</h2><p style='color:#9ca3af;'>No malicious backdoors, exposed credentials, or high vulnerabilities detected.</p></div>"}
    </div>
</body>
</html>
"""
    output_file.write_text(html_content, encoding="utf-8")
    print(f"\n\033[1;92m[OK] SupaGuard HTML Security Report Generated:\033[0m {output_file}")
    return output_file
