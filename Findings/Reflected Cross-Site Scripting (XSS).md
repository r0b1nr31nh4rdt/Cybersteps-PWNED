# Reflected Cross-Site Scripting (XSS)
Severity: Medium

CVSS 3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N — 6.1

CWE: CWE-79 (Improper Neutralization of Input During Web Page Generation)

(ergänzend: CWE-116 — Improper Encoding or Escaping of Output)
Description:

The money parameter on Deals.php is reflected into the HTML response without output encoding. User-supplied input is concatenated directly into the page markup, allowing an attacker to inject arbitrary HTML and JavaScript that executes in the victim's browser within the trust context of the application. No Content Security Policy (CSP) is present, so injected inline scripts are not restricted. The lack of encoding is further evidenced in the page source by broken markup (an orphaned closing tag) resulting from unescaped input.

Affected Component:

http://10.10.10.10/Deals.php, parameter money
http://10.10.10.10/Reviews.php, parameter score

Proof of Concept:

Deals.php
Submit a payload via the money parameter, e.g. <img src=x onerror=alert(1)>. (Screenshot)
The payload is reflected unencoded into the response and executes in the browser (JavaScript alert dialog triggered). (Screenshot)
Confirmed with a second payload <svg onload=alert(1)>, ruling out a context-specific fluke. (Screenshot)

Reviews.php
Submit a payload via the score parameter, e.g. <img src=x onerror=alert(1)>. (Screenshot)
The payload is reflected unencoded into the response and executes in the browser (JavaScript alert dialog triggered). (Screenshot)
Confirmed with a second payload <svg onload=alert(1)>, ruling out a context-specific fluke. (Screenshot)

Impact:

An attacker can craft a malicious link containing a payload in the money parameter and deliver it to a victim (e.g. via email or message). When the victim opens the link, arbitrary JavaScript executes in their session context. This enables session/cookie theft (if cookies are not protected by HttpOnly), keylogging, phishing overlays, redirection to attacker-controlled sites, and actions performed in the victim's name. As reflected XSS requires the victim to follow a prepared link, user interaction is needed.
Remediation:

In the code handling Deals.php, apply context-aware output encoding to all user-supplied data before inserting it into the HTML response (HTML entity encoding for HTML context, attribute/JS/URL encoding as appropriate). Do not concatenate raw input into markup. Implement a restrictive Content Security Policy as defense-in-depth to limit inline script execution. Set the HttpOnly flag on session cookies to reduce the impact of any residual XSS.