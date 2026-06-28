Finding X: Sensitive Credentials Transmitted via GET Request
Severity: Medium

CVSS 3.1: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N — 3.7

CWE: CWE-598 (Use of GET Request Method With Sensitive Query Strings)
Description:

The login form on Admin.php submits credentials using the HTTP GET method. As a result, the Email and Password values are placed in the URL query string. Credentials in URLs are exposed in browser history, server access logs, proxy logs, and the Referer header sent to third-party resources, significantly increasing the risk of credential leakage.
Affected Component:

http://10.10.10.10/Admin.php, parameters Email and Password (HTTP GET)
Proof of Concept:

Submit the login form on Admin.php. (Screenshot)
Observe that the request uses GET and the credentials appear in the URL: Admin.php?Email=...&Password=.... (Screenshot)

Impact:

Credentials submitted via GET are persisted in multiple locations outside the application's control — browser history on shared machines, web server and proxy access logs, and potentially the Referer header. Anyone with access to these logs or the user's browser can recover the credentials. This is an exposure/disclosure risk rather than a directly exploitable flaw, which is reflected in the lower score.
Remediation:

Change the login form to use the HTTP POST method so credentials are sent in the request body rather than the URL. Enforce HTTPS for all authentication traffic. Ensure credentials are never logged. Review existing server logs and browser environments for already-leaked credentials and rotate any affected accounts.

