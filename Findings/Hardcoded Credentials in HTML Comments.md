# Hardcoded Credentials in HTML Comments
Severity: High

CVSS 3.1: 7.5 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

CWE: CWE-615 (Information Exposure Through Comments)
Affected Component: http://10.10.10.10/dashboard (dashboard.html) — valid credentials disclosed within an HTML comment in the page source
Description: The login page served at /dashboard contains valid guest account credentials inside an HTML comment. Any unauthenticated user can view the page source and extract working credentials, bypassing the intended authentication barrier.
Proof of Concept:

Navigate to http://10.10.10.10/dashboard
Open the page source (Ctrl+U) / view via Burp
Locate the HTML comment containing the credentials (Screenshot)
Log in with the disclosed guest credentials → valid session cookie issued (Screenshot)

Remediation: Remove the credentials from the HTML comment in dashboard.html. Rotate/disable the exposed guest account. Establish a process/code-review step to prevent secrets in source comments (e.g. pre-commit secret scanning).