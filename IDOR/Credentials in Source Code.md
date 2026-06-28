# Credentials in Source Code

## CWE-615 — Information Exposure Through Comments

Working Credentials in Comments

```
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Login — CyberSteps Dashboard</title>
<!--
    CyberSteps Customer Dashboard
    TODO: Remove before production!
    Demo access: guest@cyberstepsvuln.com / guest123
-->
<style>
```


## Findings
Finding 1: Hardcoded Credentials in HTML Comments
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





Finding X: Privilege Escalation via Cookie Manipulation
Severity: High

CVSS 3.1: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N — 8.7

CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)

(ergänzend: CWE-269 — Improper Privilege Management; CWE-302 — Authentication Bypass by Assumed-Immutable Data)
Description:

The application stores authorization-relevant data (the user role / identifier) in a client-side cookie without server-side validation or integrity protection. By modifying this cookie value, an authenticated guest user can assume the identity and privileges of other accounts, including an administrative account. The server trusts client-controlled data to make authorization decisions.
Affected Component:

Session cookie [cookie-name] on http://10.10.10.10/dashboard
Proof of Concept:

Log in as guest (using the credentials from the HTML comment finding) and inspect the issued cookie. (Screenshot)
Identify the authorization-relevant field, e.g. role=guest. (Screenshot)
Modify the value to role=admin via browser dev tools / Burp. (Screenshot)
Resend the request → administrative access granted, all user accounts visible. (Screenshot)

Impact:

Any authenticated low-privilege user can escalate to administrative privileges by editing a single cookie value, with no further exploitation required. This grants unauthorized access to all user accounts and administrative views, breaking the application's access control model entirely. Combined with the exposed guest credentials (HTML comment finding), an unauthenticated attacker can reach administrative access through a short chain.
Remediation:

Never store authorization data (role, user ID, privilege flags) in client-controlled cookies. Hold session state server-side and reference it via an opaque, random session identifier. Enforce all authorization checks server-side on every request based on the authenticated server-side session, not on client-supplied values. Apply integrity protection (signed/encrypted sessions) and set HttpOnly, Secure, and SameSite flags on session cookies.


