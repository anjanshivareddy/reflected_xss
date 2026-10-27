#!/usr/bin/env python3
"""
========================================================================================
IIIT ALLAHABAD - DEPARTMENT OF INFORMATION TECHNOLOGY
CYBER SECURITY (IT-30001) | AUTUMN SEMESTER 2026
ASSIGNMENT: WEB SERVER SECURITY - EXPLOITATION & MITIGATION
VULNERABILITY CATEGORY: CROSS-SITE SCRIPTING (XSS)
VARIANT: REFLECTED XSS (VARIANT 2)
========================================================================================

Demonstration Web Application: Campus Directory Search
Author: Anjan Shiva Reddy (Roll No: IIT2024265)
Instructor: Dr. Soumyadev Maity

Table 2 Viva & Walkthrough Mapping:
  (a) Vulnerable Implementation -> Route /vulnerable (Unencoded query reflection)
  (b) Working Exploit Payload   -> <script>alert('Reflected XSS Executed! Cookie: ' + document.cookie)</script>
  (c) Root Cause                -> Untrusted GET parameter concatenated directly into HTML response body
  (d) Implemented Mitigation    -> Route /secure (Context-aware HTML entity encoding via html.escape)
  (e) Other Mitigations (Theory)-> Framework auto-escaping, HTML sanitizers (DOMPurify/Bleach),
                                   Content Security Policy (CSP), HttpOnly cookies, Safe DOM sinks
"""

import html
from flask import Flask, request, make_response, redirect, url_for

app = Flask(__name__)

# ------------------------------------------------------------------------------
# Mock Data: Campus Directory Records
# ------------------------------------------------------------------------------
DIRECTORY_RECORDS = [
    {
        "name": "Alice Sharma",
        "roll": "IIT2023015",
        "role": "B.Tech Student (IT)",
        "dept": "Department of Information Technology",
        "email": "iit2023015@iiita.ac.in",
        "badge": "Student"
    },
    {
        "name": "Bob Verma",
        "roll": "IIT2023042",
        "role": "B.Tech Student (ECE)",
        "dept": "Department of Electronics & Communication",
        "email": "iit2023042@iiita.ac.in",
        "badge": "Student"
    },
    {
        "name": "Charlie Patel",
        "roll": "IIT2022108",
        "role": "M.Tech Scholar (Cyber Security)",
        "dept": "Department of Information Technology",
        "email": "mit2022108@iiita.ac.in",
        "badge": "Scholar"
    },
    {
        "name": "Dr. Soumyadev Maity",
        "roll": "FAC-IT-104",
        "role": "Course Instructor & Associate Professor",
        "dept": "Department of Information Technology",
        "email": "s.maity@iiita.ac.in",
        "badge": "Faculty"
    }
]

# Standard working XSS payload targeting session cookie
EXPLOIT_PAYLOAD = "<script>alert('Reflected XSS Executed! Cookie: ' + document.cookie)</script>"


def filter_directory(query: str):
    """Filter mock directory records by matching name, roll number, or department."""
    if not query:
        return DIRECTORY_RECORDS
    q_lower = query.lower()
    return [
        rec for rec in DIRECTORY_RECORDS
        if q_lower in rec["name"].lower()
        or q_lower in rec["roll"].lower()
        or q_lower in rec["dept"].lower()
        or q_lower in rec["role"].lower()
    ]


def build_page_template(mode: str, query: str, reflected_output: str, is_vulnerable: bool) -> str:
    """
    Renders the unified, clean single-page interface for the educational lab.
    
    Parameters:
      mode: 'vulnerable' or 'secure'
      query: the raw user query string
      reflected_output: the string placed in the reflection DOM location.
                        - In vulnerable mode: unencoded raw query
                        - In secure mode: html.escape(query)
      is_vulnerable: boolean flag indicating mode
    """
    matches = filter_directory(query)
    match_count = len(matches) if query else len(DIRECTORY_RECORDS)

    # Build directory result cards HTML
    records_html = ""
    for rec in matches:
        records_html += f"""
        <div class="directory-card">
            <div class="card-avatar">{rec['name'][0]}</div>
            <div class="card-details">
                <div class="card-header-row">
                    <h3 class="card-name">{html.escape(rec['name'])}</h3>
                    <span class="card-badge badge-{rec['badge'].lower()}">{html.escape(rec['badge'])}</span>
                </div>
                <p class="card-role">{html.escape(rec['role'])} &bull; <code>{html.escape(rec['roll'])}</code></p>
                <p class="card-dept">{html.escape(rec['dept'])}</p>
                <p class="card-email">&#9993; {html.escape(rec['email'])}</p>
            </div>
        </div>
        """

    if not matches and query:
        records_html = """
        <div class="no-results-box">
            <div class="no-results-icon">&#128269;</div>
            <h4>No directory records matched your search query</h4>
            <p>The query was processed and reflected back to the client, but no campus database records matched.</p>
        </div>
        """

    # Prepare raw inspector snippet preview (safely entity-encoded for visual display in <pre><code>)
    # This lets the student show the evaluator the exact difference in the HTTP response body.
    if is_vulnerable:
        raw_server_response_snippet = f'<span class="reflected-term">{query}</span>'
    else:
        raw_server_response_snippet = f'<span class="reflected-term">{html.escape(query)}</span>'
    safe_preview_of_server_markup = html.escape(raw_server_response_snippet)

    status_tag = (
        '<span class="status-pill status-danger">&#9888; VULNERABLE MODE (XSS ACTIVE)</span>'
        if is_vulnerable else
        '<span class="status-pill status-safe">&#10004; SECURED MODE (ENCODING ACTIVE)</span>'
    )

    action_url = "/vulnerable" if is_vulnerable else "/secure"

    # Notice: In the HTML below, the reflection placeholder:
    #   <span class="reflected-term">{reflected_output}</span>
    # In vulnerable mode, this is direct concatenation of unencoded input.
    # In secure mode, this contains the html.escape() output.
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IIITA Cyber Security Lab | Reflected XSS Demo</title>
    <style>
        :root {{
            --primary: #1e3a8a;
            --primary-light: #3b82f6;
            --danger: #dc2626;
            --danger-bg: #fef2f2;
            --danger-border: #fca5a5;
            --success: #16a34a;
            --success-bg: #f0fdf4;
            --success-border: #86efac;
            --gray-50: #f8fafc;
            --gray-100: #f1f5f9;
            --gray-200: #e2e8f0;
            --gray-300: #cbd5e1;
            --gray-600: #475569;
            --gray-700: #334155;
            --gray-800: #1e293b;
            --gray-900: #0f172a;
            --card-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
            --card-shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.05);
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }}

        body {{
            background-color: var(--gray-50);
            color: var(--gray-800);
            line-height: 1.5;
            padding-bottom: 50px;
        }}

        /* Institution Header */
        .inst-header {{
            background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%);
            color: white;
            padding: 20px 24px;
            border-bottom: 3px solid #3b82f6;
        }}
        .inst-container {{
            max-width: 1080px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }}
        .inst-titles h1 {{
            font-size: 1.35rem;
            font-weight: 700;
            letter-spacing: -0.01em;
        }}
        .inst-titles p {{
            font-size: 0.85rem;
            color: #93c5fd;
            margin-top: 3px;
        }}
        .cookie-badge {{
            background: rgba(255, 255, 255, 0.12);
            border: 1px solid rgba(255, 255, 255, 0.25);
            border-radius: 8px;
            padding: 8px 14px;
            font-size: 0.8rem;
            text-align: right;
        }}
        .cookie-badge code {{
            color: #fde047;
            font-weight: 700;
            background: rgba(0,0,0,0.3);
            padding: 2px 6px;
            border-radius: 4px;
        }}

        /* Mode Switcher Tabs */
        .tab-bar-container {{
            max-width: 1080px;
            margin: 24px auto 0 auto;
            padding: 0 20px;
        }}
        .tab-bar {{
            display: flex;
            gap: 12px;
            background: #e2e8f0;
            padding: 6px;
            border-radius: 12px;
        }}
        .tab-link {{
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 12px 18px;
            text-decoration: none;
            font-weight: 600;
            font-size: 0.95rem;
            border-radius: 8px;
            transition: all 0.2s ease;
        }}
        .tab-vulnerable {{
            color: #991b1b;
        }}
        .tab-vulnerable.active {{
            background: #ffffff;
            color: #dc2626;
            box-shadow: 0 2px 5px rgba(220, 38, 38, 0.2);
            border: 1px solid var(--danger-border);
        }}
        .tab-secure {{
            color: #166534;
        }}
        .tab-secure.active {{
            background: #ffffff;
            color: #16a34a;
            box-shadow: 0 2px 5px rgba(22, 163, 74, 0.2);
            border: 1px solid var(--success-border);
        }}

        /* Main Container */
        .main-container {{
            max-width: 1080px;
            margin: 20px auto;
            padding: 0 20px;
        }}

        /* Mode Banner */
        .mode-banner {{
            border-radius: 10px;
            padding: 16px 20px;
            margin-bottom: 24px;
            display: flex;
            align-items: flex-start;
            gap: 14px;
            box-shadow: var(--card-shadow);
        }}
        .mode-banner.danger {{
            background: var(--danger-bg);
            border-left: 5px solid var(--danger);
            color: #991b1b;
        }}
        .mode-banner.safe {{
            background: var(--success-bg);
            border-left: 5px solid var(--success);
            color: #166534;
        }}
        .banner-icon {{
            font-size: 1.5rem;
            line-height: 1;
        }}
        .banner-text h3 {{
            font-size: 1rem;
            font-weight: 700;
            margin-bottom: 4px;
        }}
        .banner-text p {{
            font-size: 0.88rem;
            opacity: 0.9;
        }}

        /* Status Pill */
        .status-pill {{
            display: inline-block;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.04em;
            padding: 3px 8px;
            border-radius: 4px;
            margin-bottom: 6px;
        }}
        .status-danger {{
            background: #fee2e2;
            color: #b91c1c;
            border: 1px solid #f87171;
        }}
        .status-safe {{
            background: #dcfce7;
            color: #15803d;
            border: 1px solid #4ade80;
        }}

        /* Card Component */
        .card {{
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: var(--card-shadow);
            border: 1px solid var(--gray-200);
        }}
        .card-title {{
            font-size: 1.15rem;
            font-weight: 700;
            color: var(--gray-900);
            margin-bottom: 6px;
        }}
        .card-subtitle {{
            font-size: 0.88rem;
            color: var(--gray-600);
            margin-bottom: 18px;
        }}

        /* Search Form */
        .search-form {{
            display: flex;
            gap: 10px;
            margin-bottom: 16px;
        }}
        .search-input {{
            flex: 1;
            padding: 12px 16px;
            font-size: 0.95rem;
            border: 2px solid var(--gray-300);
            border-radius: 8px;
            outline: none;
            transition: border-color 0.2s;
        }}
        .search-input:focus {{
            border-color: var(--primary-light);
        }}
        .btn-search {{
            background: var(--primary);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.95rem;
            cursor: pointer;
            transition: background 0.2s;
        }}
        .btn-search:hover {{
            background: #1e40af;
        }}

        /* Quick Payload Injector */
        .quick-tests {{
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            padding: 12px 14px;
            background: var(--gray-100);
            border-radius: 8px;
            font-size: 0.85rem;
        }}
        .quick-tests-label {{
            font-weight: 600;
            color: var(--gray-700);
        }}
        .btn-quick {{
            background: white;
            border: 1px solid var(--gray-300);
            border-radius: 6px;
            padding: 6px 12px;
            font-size: 0.82rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s ease;
            color: var(--gray-800);
        }}
        .btn-quick:hover {{
            background: var(--gray-200);
        }}
        .btn-quick-exploit {{
            background: #fee2e2;
            color: #991b1b;
            border-color: #fca5a5;
            font-weight: 600;
        }}
        .btn-quick-exploit:hover {{
            background: #fecaca;
        }}

        /* Reflection Box */
        .reflection-card {{
            border-left: 4px solid var(--primary-light);
            background: #ffffff;
            margin-bottom: 24px;
        }}
        .reflection-result-header {{
            font-size: 1.05rem;
            color: var(--gray-800);
            margin-bottom: 6px;
        }}
        .reflected-term {{
            font-weight: 700;
            color: var(--primary);
            background: #eff6ff;
            padding: 2px 8px;
            border-radius: 4px;
            border: 1px dashed #bfdbfe;
            display: inline-block;
        }}

        /* Directory Cards Grid */
        .directory-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(310px, 1fr));
            gap: 16px;
            margin-top: 14px;
        }}
        .directory-card {{
            background: #ffffff;
            border: 1px solid var(--gray-200);
            border-radius: 10px;
            padding: 16px;
            display: flex;
            gap: 14px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            transition: transform 0.15s ease;
        }}
        .directory-card:hover {{
            transform: translateY(-2px);
            box-shadow: var(--card-shadow);
        }}
        .card-avatar {{
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, #1e3a8a, #3b82f6);
            color: white;
            font-weight: 700;
            font-size: 1.2rem;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            flex-shrink: 0;
        }}
        .card-details {{
            flex: 1;
            min-width: 0;
        }}
        .card-header-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 4px;
        }}
        .card-name {{
            font-size: 0.98rem;
            font-weight: 700;
            color: var(--gray-900);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .card-badge {{
            font-size: 0.7rem;
            font-weight: 600;
            padding: 2px 6px;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge-faculty {{
            background: #fef3c7;
            color: #92400e;
        }}
        .badge-student {{
            background: #e0f2fe;
            color: #0369a1;
        }}
        .badge-scholar {{
            background: #f3e8ff;
            color: #7e22ce;
        }}
        .card-role {{
            font-size: 0.8rem;
            color: var(--gray-700);
            margin-bottom: 2px;
        }}
        .card-role code {{
            background: var(--gray-100);
            padding: 1px 4px;
            border-radius: 3px;
        }}
        .card-dept {{
            font-size: 0.78rem;
            color: var(--gray-600);
            margin-bottom: 4px;
        }}
        .card-email {{
            font-size: 0.76rem;
            color: #2563eb;
        }}

        .no-results-box {{
            text-align: center;
            padding: 32px 16px;
            color: var(--gray-600);
        }}
        .no-results-icon {{
            font-size: 2.2rem;
            margin-bottom: 8px;
        }}

        /* Raw Inspector Box */
        .inspector-box {{
            background: #0f172a;
            color: #e2e8f0;
            border-radius: 10px;
            padding: 18px 20px;
            margin-top: 24px;
            border: 1px solid #334155;
        }}
        .inspector-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            border-bottom: 1px solid #334155;
            padding-bottom: 8px;
        }}
        .inspector-header h4 {{
            font-size: 0.9rem;
            font-weight: 600;
            color: #94a3b8;
            letter-spacing: 0.02em;
        }}
        .inspector-badge {{
            font-size: 0.75rem;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 600;
        }}
        .inspector-badge.raw {{
            background: #7f1d1d;
            color: #fca5a5;
        }}
        .inspector-badge.encoded {{
            background: #14532d;
            color: #86efac;
        }}
        .inspector-code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.82rem;
            background: #020617;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            color: #38bdf8;
            line-height: 1.4;
        }}
        .inspector-note {{
            font-size: 0.78rem;
            color: #94a3b8;
            margin-top: 10px;
        }}

        /* Viva Checklist Card */
        .viva-card {{
            background: #ffffff;
            border-top: 4px solid #6366f1;
        }}
        .viva-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-top: 12px;
        }}
        @media (max-width: 768px) {{
            .viva-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        .viva-item {{
            background: var(--gray-50);
            border: 1px solid var(--gray-200);
            border-radius: 8px;
            padding: 14px;
        }}
        .viva-item-title {{
            font-size: 0.85rem;
            font-weight: 700;
            color: var(--gray-800);
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .viva-item-desc {{
            font-size: 0.8rem;
            color: var(--gray-600);
            line-height: 1.45;
        }}
        .viva-item-desc code {{
            background: #e2e8f0;
            color: #0f172a;
            padding: 1px 4px;
            border-radius: 3px;
            font-size: 0.75rem;
        }}
    </style>
</head>
<body>

    <!-- Institutional Header -->
    <header class="inst-header">
        <div class="inst-container">
            <div class="inst-titles">
                <h1>IIIT Allahabad &bull; Department of Information Technology</h1>
                <p>Cyber Security (IT-30001) &bull; Reflected XSS Vulnerability & Defense Lab &bull; <strong>Roll No: IIT2024265</strong></p>
            </div>
            <div class="cookie-badge">
                <div>Demo Session Cookie:</div>
                <code>demo_session=IIITA_Student_123</code>
            </div>
        </div>
    </header>

    <!-- Navigation Tabs -->
    <div class="tab-bar-container">
        <div class="tab-bar">
            <a href="/vulnerable{f'?q={query}' if query else ''}" class="tab-link tab-vulnerable {'active' if is_vulnerable else ''}" id="tab-vulnerable">
                <span>&#9888;</span> Mode 1: Vulnerable Endpoint (<code>/vulnerable</code>)
            </a>
            <a href="/secure{f'?q={query}' if query else ''}" class="tab-link tab-secure {'active' if not is_vulnerable else ''}" id="tab-secure">
                <span>&#128737;</span> Mode 2: Secured Endpoint (<code>/secure</code>)
            </a>
        </div>
    </div>

    <!-- Main Container -->
    <main class="main-container">

        <!-- Dynamic Status Banner -->
        <div class="mode-banner {'danger' if is_vulnerable else 'safe'}">
            <div class="banner-icon">{'&#9888;' if is_vulnerable else '&#128737;'}</div>
            <div class="banner-text">
                {status_tag}
                <h3>{'Vulnerable State: Direct Unencoded Reflection' if is_vulnerable else 'Secured State: Context-Aware HTML Entity Encoding'}</h3>
                <p>
                    {'User input from the GET parameter <code>q</code> is concatenated directly into the HTML response stream without encoding. An attacker-supplied script tag will execute in the browser context.' if is_vulnerable else
                     'User input is passed through Python\'s <code>html.escape()</code> prior to reflection. Dangerous characters (<code>&lt;</code>, <code>&gt;</code>, <code>&amp;</code>, <code>&quot;</code>, <code>&#x27;</code>) become inert HTML entities.'}
                </p>
            </div>
        </div>

        <!-- Campus Search Form Card -->
        <div class="card">
            <h2 class="card-title">&#128269; Campus Directory Search</h2>
            <p class="card-subtitle">Query campus faculty, researchers, and students by name, roll number, or department.</p>

            <form action="{action_url}" method="GET" class="search-form" id="search-form">
                <input 
                    type="text" 
                    name="q" 
                    id="search-input" 
                    class="search-input" 
                    placeholder="Enter search term (e.g. Alice, Bob, Dr. Maity)..." 
                    value="{html.escape(query)}"
                    autocomplete="off"
                >
                <button type="submit" class="btn-search" id="btn-submit">Search</button>
            </form>

            <!-- Quick-Test Action Buttons -->
            <div class="quick-tests">
                <span class="quick-tests-label">Quick Tests for Viva Demo:</span>
                <button type="button" class="btn-quick" onclick="fillAndSubmit('Alice')">
                    &#128100; Normal Input: "Alice"
                </button>
                <button type="button" class="btn-quick btn-quick-exploit" onclick="fillAndSubmit('<script>alert(\\'Reflected XSS Executed! Cookie: \\' + document.cookie)<\\/script>')">
                    &#9889; Exploit Payload: &lt;script&gt;alert(cookie)&lt;/script&gt;
                </button>
                <button type="button" class="btn-quick" onclick="fillInput('')">
                    &#10006; Clear
                </button>
            </div>
        </div>

        <!-- Reflection & Search Results Card -->
        <div class="card reflection-card">
            <div class="reflection-result-header">
                {'Showing search results for: ' if query else 'Browse Full Campus Directory (4 records)'}
                {f'<span class="reflected-term" id="reflected-output">{reflected_output}</span>' if query else ''}
            </div>
            <p style="font-size: 0.85rem; color: var(--gray-600); margin-bottom: 12px;">
                {'Matched ' + str(match_count) + ' record(s).' if query else 'Use the search box above to filter or test input reflection.'}
            </p>

            <div class="directory-grid">
                {records_html}
            </div>
        </div>

        <!-- Raw Server Output Box for Evaluator Comparison -->
        <div class="inspector-box">
            <div class="inspector-header">
                <h4>RAW SERVER RESPONSE INSPECTOR (VIVA EVIDENCE)</h4>
                <span class="inspector-badge {'raw' if is_vulnerable else 'encoded'}">
                    {'RAW UNENCODED HTML' if is_vulnerable else 'HTML ENTITY ENCODED'}
                </span>
            </div>
            <p style="font-size: 0.82rem; color: #cbd5e1; margin-bottom: 8px;">
                HTTP Response fragment delivered by the Flask web server to the client browser:
            </p>
            <div class="inspector-code">
                <code>{safe_preview_of_server_markup}</code>
            </div>
            <div class="inspector-note">
                {'&#9888; <strong>Evaluator Note:</strong> In Vulnerable Mode, notice how <code>&lt;script&gt;</code> tags exist verbatim in the HTTP response body. The browser HTML parser encounters the tag and executes the JavaScript immediately.' if is_vulnerable else
                 '&#10004; <strong>Evaluator Note:</strong> In Secured Mode, notice how <code>&lt;script&gt;</code> is transformed into safe entities <code>&amp;lt;script&amp;gt;</code>. The browser treats this strictly as character data and will not execute it.'}
            </div>
        </div>

        <!-- Viva & Walkthrough Checklist (Table 2 Reference) -->
        <div class="card viva-card" style="margin-top: 24px;">
            <h2 class="card-title">&#128218; Assignment Reference & Viva Walkthrough (Table 2)</h2>
            <p class="card-subtitle">Quick reference points to explain each subsection live to the evaluator.</p>

            <div class="viva-grid">
                <div class="viva-item">
                    <div class="viva-item-title">&#128308; (a) Vulnerable Implementation</div>
                    <div class="viva-item-desc">
                        Code path: <code>@app.route('/vulnerable')</code>.<br>
                        Accepts parameter <code>request.args.get('q', '')</code> and concatenates it directly into the HTML string without encoding.
                    </div>
                </div>

                <div class="viva-item">
                    <div class="viva-item-title">&#9889; (b) Working Exploit</div>
                    <div class="viva-item-desc">
                        Payload: <code>&lt;script&gt;alert('Reflected XSS Executed! Cookie: ' + document.cookie)&lt;/script&gt;</code>.<br>
                        Triggers execution in the user's browser context and accesses <code>document.cookie</code>.
                    </div>
                </div>

                <div class="viva-item">
                    <div class="viva-item-title">&#129300; (c) Root Cause</div>
                    <div class="viva-item-desc">
                        Lack of separation between code and data. Untrusted user data is interpreted as executable markup because the server failed to apply contextual encoding prior to reflection.
                    </div>
                </div>

                <div class="viva-item">
                    <div class="viva-item-title">&#128737; (d) Mitigation Implemented</div>
                    <div class="viva-item-desc">
                        Code path: <code>@app.route('/secure')</code>.<br>
                        Employs <strong>Context-Aware HTML Entity Encoding</strong> via Python's <code>html.escape(q)</code>. Neutralizes characters like <code>&lt;</code>, <code>&gt;</code>, <code>&amp;</code>, <code>&quot;</code>, <code>&#x27;</code>.
                    </div>
                </div>
            </div>

            <div class="viva-item" style="margin-top: 14px;">
                <div class="viva-item-title">&#128214; (e) Other Mitigations (Theory from Lecture Slides)</div>
                <div class="viva-item-desc">
                    <strong>1. Framework Auto-Escaping:</strong> Modern templating engines (e.g., Jinja2) escape variables by default unless explicitly disabled.<br>
                    <strong>2. HTML Sanitizers:</strong> Libraries like <em>DOMPurify</em> or <em>Bleach</em> allow safe rich-text formatting (e.g., <code>&lt;b&gt;</code>) while stripping scripts.<br>
                    <strong>3. Content Security Policy (CSP):</strong> HTTP header <code>Content-Security-Policy: default-src 'self'</code> restricts untrusted inline scripts and origins.<br>
                    <strong>4. HttpOnly Cookies:</strong> Flag <code>Set-Cookie: session=...; HttpOnly</code> prevents JavaScript access via <code>document.cookie</code>, blunting session hijacking.<br>
                    <strong>5. Safe DOM Sinks:</strong> Using <code>element.textContent</code> instead of <code>element.innerHTML</code> or <code>document.write()</code>.
                </div>
            </div>
        </div>

    </main>

    <script>
        // Quick helper functions for live screen recording & viva demonstration
        function fillAndSubmit(val) {{
            var input = document.getElementById('search-input');
            input.value = val;
            document.getElementById('search-form').submit();
        }}

        function fillInput(val) {{
            var input = document.getElementById('search-input');
            input.value = val;
            input.focus();
        }}
    </script>
</body>
</html>
"""
    return html_content


# ------------------------------------------------------------------------------
# Default Route: Redirects to Vulnerable Endpoint
# ------------------------------------------------------------------------------
@app.route('/')
def index():
    """Redirect home requests to the vulnerable search endpoint by default."""
    return redirect(url_for('vulnerable_search'))


# ------------------------------------------------------------------------------
# Route 1: Vulnerable Implementation
# ------------------------------------------------------------------------------
@app.route('/vulnerable')
def vulnerable_search():
    """
    Vulnerable Search Endpoint:
    Receives user query 'q' via GET parameter and directly reflects it into HTML.
    """
    # Extract query parameter from the HTTP GET request
    query = request.args.get('q', '')

    # ==========================================================================
    # (a) VULNERABLE IMPLEMENTATION: Unencoded user input reflected directly in HTML.
    # ==========================================================================
    # The server accepts the user-supplied 'q' parameter and concatenates it
    # directly into the HTML response document WITHOUT entity encoding or sanitization.
    # When the client browser parses the returned HTML, any script tags or event
    # handlers in 'query' will be executed in the victim's browser session.
    reflected_output = query

    # Render HTML page with the raw, unencoded reflection
    rendered_html = build_page_template(
        mode='vulnerable',
        query=query,
        reflected_output=reflected_output,
        is_vulnerable=True
    )

    # Wrap in Flask response to attach non-sensitive session cookie for live proof
    response = make_response(rendered_html)

    # Set non-sensitive session cookie so the alert() payload can visibly prove access.
    # Note: HttpOnly is deliberately NOT set on this dummy cookie to demonstrate
    # the security impact of cookie theft via document.cookie.
    response.set_cookie('demo_session', 'IIITA_Student_123', samesite='Lax')
    return response


# ------------------------------------------------------------------------------
# Route 2: Secured Implementation
# ------------------------------------------------------------------------------
@app.route('/secure')
def secure_search():
    """
    Secured Search Endpoint:
    Receives user query 'q' and applies context-aware HTML entity encoding.
    """
    # Extract query parameter from the HTTP GET request
    query = request.args.get('q', '')

    # ==========================================================================
    # (d) MITIGATION IMPLEMENTED: Context-aware HTML entity encoding.
    # ==========================================================================
    # Python's built-in html.escape() performs context-aware entity encoding for HTML body:
    #   '&' -> '&amp;'
    #   '<' -> '&lt;'
    #   '>' -> '&gt;'
    #   '"' -> '&quot;'
    #   "'" -> '&#x27;'
    # This guarantees that characters with special meaning in the HTML grammar are
    # treated purely as visual character data by the browser's DOM parser, completely
    # preventing the browser from interpreting the input as executable JavaScript.
    safe_query = html.escape(query)
    reflected_output = safe_query

    # Render HTML page with the safely encoded reflection
    rendered_html = build_page_template(
        mode='secure',
        query=query,
        reflected_output=reflected_output,
        is_vulnerable=False
    )

    # Wrap in Flask response and set same non-sensitive session cookie
    response = make_response(rendered_html)
    response.set_cookie('demo_session', 'IIITA_Student_123', samesite='Lax')
    return response


# ------------------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    # Running on 127.0.0.1:5001 (or 5000) for local testing and video demonstration
    print("==================================================================")
    print(" IIIT Allahabad - Web Server Security Assignment")
    print(" Reflected XSS Demo Server running at: http://127.0.0.1:5001/")
    print("   -> Vulnerable Endpoint: http://127.0.0.1:5001/vulnerable")
    print("   -> Secured Endpoint:    http://127.0.0.1:5001/secure")
    print("==================================================================")
    app.run(host='127.0.0.1', port=5001, debug=True)
