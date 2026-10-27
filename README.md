# Web Server Security: Reflected Cross-Site Scripting (XSS) Demonstration & Defense

**Course:** Cyber Security (IT-30001) | Autumn Semester 2026  
**Department:** Department of Information Technology  
**Institution:** Indian Institute of Information Technology Allahabad (IIIT Allahabad)  
**Instructor:** Dr. Soumyadev Maity  

---

## 1. Ownership Declaration (Table 3)

| Member name | Roll number | Category | Variant implemented |
| :--- | :--- | :--- | :--- |
| **Anjan Shiva Reddy** | **IIT2024265** | Cross-Site Scripting (XSS) | Variant 2: Reflected XSS |

---

## 2. Project Architecture & Scenario

This project models a **"Campus Directory Search"** web service where campus members search for faculty, scholars, and students. The application demonstrates **Reflected Cross-Site Scripting (Reflected XSS)** and its primary defense:

- **Endpoint 1 (`/vulnerable`):** Unsanitized input reflection directly into the HTML response document.
- **Endpoint 2 (`/secure`):** Context-aware HTML entity encoding using Python's standard `html.escape()`.
- **Dummy Session Cookie (`demo_session=IIITA_Student_123`):** Injected on page load without the `HttpOnly` flag so the JavaScript payload visibly proves session cookie exfiltration.
- **Raw Server Output Inspector:** A live inspection box on the UI displaying the raw HTTP response delivered by the server so the evaluator can visually verify whether `<script>` stays executable or is neutralized into `&lt;script&gt;`.

```mermaid
sequenceDiagram
    autonumber
    actor Victim as User / Evaluator Browser
    participant Flask as Flask Server (app.py)
    
    Note over Victim,Flask: Scenario 1: Vulnerable Endpoint (/vulnerable)
    Victim->>Flask: GET /vulnerable?q=<script>alert(document.cookie)</script>
    Flask-->>Victim: HTTP 200 OK: ...Showing results for: <script>alert(document.cookie)</script>...
    Note over Victim: Browser parser executes raw <script> tag!
    Victim->>Victim: Alert popup fires displaying: demo_session=IIITA_Student_123

    Note over Victim,Flask: Scenario 2: Secured Endpoint (/secure)
    Victim->>Flask: GET /secure?q=<script>alert(document.cookie)</script>
    Note over Flask: html.escape() transforms < > & " '
    Flask-->>Victim: HTTP 200 OK: ...Showing results for: &lt;script&gt;alert(document.cookie)&lt;/script&gt;...
    Note over Victim: Browser treats entities strictly as text! Zero JS execution.
```

---

## 3. Quick Start & Execution Guide

### Prerequisites
- Python 3.9+ (Python 3.10, 3.11, 3.12, 3.13, 3.14 supported)

### Step 1: Clone / Navigate to the Repository
```bash
git clone <your-group-github-repo-url>
cd cyber
```

### Step 2: Initialize Virtual Environment & Install Dependencies
```bash
# Create local virtual environment
python3 -m venv .venv

# Activate virtual environment
# On macOS/Linux:
source .venv/bin/activate
# On Windows (cmd):
# .venv\Scripts\activate.bat

# Install dependencies (Flask)
pip install -r requirements.txt
```

### Step 3: Run the Flask Web Application
```bash
python3 app.py
```
*The application starts on `http://127.0.0.1:5001/` (or port 5000 if 5001 is occupied).*

### Step 4: Open in Web Browser
Open your browser and navigate to:
```
http://127.0.0.1:5001/
```
*(Automatically redirects to the `/vulnerable` mode with navigation tabs).*

---

## 4. Viva & Video Walkthrough Guide (Table 2 Items)

Use this section as your exact speaking notes during the 2–3 minute individual video recording and live viva defense before Dr. Soumyadev Maity.

### (a) Vulnerable Implementation
- **Source Code File:** [`app.py`](file:///Users/anjan/Desktop/cyber/app.py#L847-L880)
- **Vulnerable Function:** `vulnerable_search()` at route `@app.route('/vulnerable')`
- **Flawed Code Snippet:**
  ```python
  # ==========================================================================
  # (a) VULNERABLE IMPLEMENTATION: Unencoded user input reflected directly in HTML.
  # ==========================================================================
  query = request.args.get('q', '')
  reflected_output = query  # Direct unencoded reflection into HTML string
  ```
- **Explanation:**  
  The endpoint extracts parameter `q` from the HTTP GET query string. Instead of treating this parameter as untrusted data, the backend concatenates `query` directly into the HTML response document returned to the client browser.

---

### (b) Working Exploit
- **Exact Attack Payload:**
  ```html
  <script>alert('Reflected XSS Executed! Cookie: ' + document.cookie)</script>
  ```
- **Exploit URL (Direct Click / cURL):**
  ```
  http://127.0.0.1:5001/vulnerable?q=%3Cscript%3Ealert('Reflected+XSS+Executed!+Cookie:+'+%2B+document.cookie)%3C/script%3E
  ```
- **Evidence of Execution:**  
  1. Click the quick-test button: **"⚡ Exploit Payload: `<script>alert(cookie)</script>`"** or paste the payload into the search bar on `/vulnerable`.
  2. The browser immediately halts DOM rendering and renders an alert modal dialog displaying:
     ```
     Reflected XSS Executed! Cookie: demo_session=IIITA_Student_123
     ```
  3. This proves that an attacker can execute arbitrary JavaScript within the origin context and exfiltrate session credentials.

---

### (c) Root Cause Analysis
- **Root Cause:**  
  **Failure to separate code from data in the web response.**  
  The HTTP server takes unvalidated, untrusted user data supplied in an HTTP GET parameter and inserts it directly into the HTML document context without contextual encoding or sanitization.
- **Why it Works:**  
  When the victim's browser parses the returned HTML response body, the browser's HTML parser cannot differentiate between legitimate HTML markup written by the developer and malicious markup injected by the user. Consequently, the browser treats `<script>` as an instruction to switch into JavaScript execution mode, executing the attacker's script under the application's origin permissions.

---

### (d) Mitigation Implemented
- **Source Code File:** [`app.py`](file:///Users/anjan/Desktop/cyber/app.py#L886-L928)
- **Mitigated Function:** `secure_search()` at route `@app.route('/secure')`
- **Mitigation Technique:** **Context-Aware HTML Entity Encoding** via Python's built-in `html.escape()`
- **Fixed Code Snippet:**
  ```python
  # ==========================================================================
  # (d) MITIGATION IMPLEMENTED: Context-aware HTML entity encoding.
  # ==========================================================================
  query = request.args.get('q', '')
  safe_query = html.escape(query)  # Context-aware HTML entity encoding
  reflected_output = safe_query
  ```
- **Transformation Mapping:**
  | Character | Dangerous Context | Replaced Safe HTML Entity |
  | :---: | :--- | :---: |
  | `<` | Opens an HTML tag (`<script>`) | `&lt;` |
  | `>` | Closes an HTML tag | `&gt;` |
  | `&` | Entity reference delimiter | `&amp;` |
  | `"` | Breaks out of quoted attribute | `&quot;` |
  | `'` | Breaks out of single-quoted attribute | `&#x27;` |

- **Verification of Defense:**  
  1. Switch to the **Secured Mode (`/secure`)** using the top tab.
  2. Submit the identical exploit payload: `<script>alert('Reflected XSS Executed! Cookie: ' + document.cookie)</script>`.
  3. **Result:** No alert pop-up appears. The payload is rendered harmlessly on screen as plain text: `Showing search results for: <script>alert(...)</script>`.
  4. Inspect the **Raw Server Response Inspector** box at the bottom of the page: the HTTP response contains `&lt;script&gt;` instead of `<script>`, demonstrating that the browser DOM parser treated the input purely as visual character data.

---

### (e) Theory of Other XSS Mitigations (From Lecture Slides)

As required by Table 2 item (e), here is the theoretical summary of alternative industry mitigations discussed in the lecture:

1. **Framework Auto-Escaping:**
   - *How it works:* Modern server-side templating frameworks (e.g., Jinja2 in Flask, Django Templates, Angular, React JSX) enforce contextual auto-escaping by default. Unless a developer explicitly marks a variable as trusted using unsafe directives (like `|safe` in Jinja2 or `dangerouslySetInnerHTML` in React), any variable rendered into the template automatically undergoes HTML entity encoding.
   
2. **HTML Sanitizers for Rich HTML Content:**
   - *How it works:* In scenarios where users must be allowed to submit formatted markup (e.g., blogs, forums, comments with `<b>`, `<i>`, `<a>`), entity encoding cannot be used because it destroys the desired formatting. Instead, robust sanitization libraries (such as *DOMPurify* on the client or *Bleach* on the server) parse the input against an explicit allow-list of safe tags and attributes, stripping out `<script>`, `<iframe>`, `onload`, `onerror`, and `javascript:` URIs.

3. **Content Security Policy (CSP):**
   - *How it works:* A defense-in-depth HTTP response header sent by the server (e.g., `Content-Security-Policy: default-src 'self'; script-src 'self'`). It instructs the browser to block inline script blocks (such as `<script>alert(1)</script>` or `onclick=...`) and only execute scripts loaded from explicitly trusted origins or matching cryptographic nonces (`nonce-xxxx`). Even if unencoded reflection occurs, CSP blocks script execution.

4. **HttpOnly Cookie Flag:**
   - *How it works:* When issuing sensitive session cookies, the server sets the directive: `Set-Cookie: session_id=...; Secure; HttpOnly; SameSite=Lax`. The `HttpOnly` flag instructs the browser that the cookie must never be accessible via client-side scripts (`document.cookie`). Although this does not prevent XSS execution, it eliminates the single most common impact of XSS: credential and session theft.

5. **Safe DOM Sinks:**
   - *How it works:* In client-side JavaScript, vulnerabilities occur when user data flows into execution-capable DOM sinks like `element.innerHTML`, `outerHTML`, `document.write()`, or `eval()`. Developers mitigate this by writing to safe, non-executable sinks such as `element.textContent` or `element.innerText`, ensuring the browser treats the input strictly as string text.

---

## 5. Live Screen Recording Script (2 to 3 Minutes)

Use this step-by-step walkthrough script for recording your video:

| Time | Action | What to Say / Demonstrate |
| :---: | :--- | :--- |
| **0:00 - 0:30** | Show Ownership Table & App Overview | *"Hello, I am Anjan Shiva Reddy, Roll Number IIT2024265. For our Web Server Security assignment in IT-30001 under Dr. Soumyadev Maity, I am demonstrating Category: Cross-Site Scripting (XSS), Variant 2: Reflected XSS."* |
| **0:30 - 1:00** | Demonstrate (a) Vulnerable Mode & (b) Exploit | *"Here is the Campus Directory Search. In Vulnerable Mode (`/vulnerable`), notice the session cookie `demo_session=IIITA_Student_123`. When I submit a normal search for 'Alice', it displays Alice's directory card. Now, I inject the working XSS payload: `<script>alert('Reflected XSS Executed! Cookie: ' + document.cookie)</script>`. Upon submitting, the browser immediately executes the script, popping up the alert showing cookie access."* |
| **1:00 - 1:40** | Explain (c) Root Cause & Code Path | *"The root cause is unencoded reflection at line 857 of `app.py`. The server took untrusted query parameter `q` and directly concatenated it into the HTML stream. As shown in the Raw Server Inspector box below, raw `<script>` tags were delivered in the response body, causing the browser parser to execute them."* |
| **1:40 - 2:20** | Demonstrate (d) Mitigation & Tab Switch | *"Now, switching to Secured Mode (`/secure`) via the top tab. Submitting the identical exploit payload: the script does NOT execute! The search term is safely printed as literal text. In `app.py` line 896, we implemented context-aware HTML entity encoding using Python's `html.escape()`. As shown in the Inspector box, `<script>` was transformed into safe entities `&lt;script&gt;`."* |
| **2:20 - 2:50** | Summarize (e) Other Mitigations | *"Beyond entity encoding, lecture-covered mitigations include: framework auto-escaping in Jinja2, HTML sanitizers like DOMPurify for rich text, Content Security Policy (CSP) to block inline scripts, HttpOnly cookie flags to prevent cookie theft, and using safe DOM sinks like `textContent`."* |

---

## 6. Directory Structure

```
cyber/
├── app.py              # Self-contained Flask application with routes, UI, and comments
├── requirements.txt    # Frozen Python dependencies (Flask 3.x)
├── README.md           # Documentation, Table 3 Ownership, and Viva Reference
└── .venv/              # Isolated Python virtual environment
```

---

## 7. Verification & Automated Test Commands

To verify both endpoints via terminal/command-line:

```bash
# 1. Test Vulnerable Reflection (Raw <script> returned in HTTP response)
curl -s "http://127.0.0.1:5001/vulnerable?q=%3Cscript%3Ealert(1)%3C/script%3E" | grep "reflected-output"

# 2. Test Secured Reflection (Encoded &lt;script&gt; returned in HTTP response)
curl -s "http://127.0.0.1:5001/secure?q=%3Cscript%3Ealert(1)%3C/script%3E" | grep "reflected-output"
```
