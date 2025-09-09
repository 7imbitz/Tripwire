# Tripwire

Burp Suite Extension for Detecting "Low-Hanging Fruit" SQL Injection Vulnerabilities

Tripwire is a Burp Suite extension that automates the detection of common SQL Injection (SQLi) vulnerabilities. It is designed to assist security testers by highlighting potential SQLi issues during manual testing, saving time and effort when identifying "low-hanging fruit" injection points.

# 📦 Installation

1. Download Burp Suite
    Get the latest version from: [PortSwigger Burp Suite](http://portswigger.net/burp/download.html)
2. Download Jython Standalone JAR
    Obtain the Jython standalone JAR from: [Jython Downloads](http://www.jython.org/download.html)
3. Configure Python Environment in Burp
    - Go to Extender → Options → Python Environment.
    - Select the downloaded Jython standalone JAR.
4. Clone Tripwire
```bash
git clone https://github.com/7imbitz/Tripwire.git
```
5. Load Extension
    - In Burp, navigate to Extender → Extensions → Add.
    - Choose the extension.py file from the Tripwire source code.
6. Verify Installation
    A new Tripwire tab should appear in Burp Suite.

# 🛠 User Guide

1. After installation, open the Tripwire tab in Burp Suite.
2. Go to the Configuration tab to control logging.
    - The "Capture ON" button enables or disables traffic capture (enabled by default).
4. Browse the target application as usual; Tripwire will automatically analyze requests with parameters.
5. If potential SQLi is detected, the Result column will display "Possible(?)".
6. An Evidence tab will be created, showing the response body with highlighted SQL-related keywords.
7. Review the highlighted response and manually confirm whether the vulnerability is exploitable.

# 🔍 Detection Methodology

Tripwire inspects responses for common SQL error fingerprints after injecting payloads into request parameters.

**SQL error signatures:**
```python
sql_errors = [
    "sql syntax", "mysql", "odbc", "oracle", "ora-",
    "unclosed quotation mark", "syntax error", "postgresql", "sqlite"
]
```

If any of these keywords are detected in the modified response, the request is flagged as "Possible(?)".

# 🚫 Requests Ignored by Tripwire

- Static files
    Requests for static assets are excluded to reduce noise:
```arduino
.js, .css, .png, .jpg, .jpeg, .gif, .ico,
.svg, .woff, .woff2, .ttf, .eot, .map, .mp4, .webm
```

- Unwanted paths
    Requests containing logging or telemetry keywords are skipped:
```arduino
log, metrics, analytics, tracking, telemetry, ads
```

- Unsupported Content-Types
    Only the following response types are processed:
```arduino
text/html, json, xml, x-www-form-urlencoded
```

# ⚠ Current Limitations

- Log Management: The Configuration panel currently lacks a "Clear Logs" option.
- Scope Restriction: Only in-scope requests should ideally be analyzed, but this feature is not yet implemented.
- Evidence View: Evidence is displayed in a text viewer rather than a Burp-style message editor.