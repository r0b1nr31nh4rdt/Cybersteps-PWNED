# XSS

## Auf Deals.php (Shop, money-POST-Parameter):

1. Business Logic Flaw — Preis (money) wird client-seitig bestimmt statt serverseitig anhand Plan-ID → Enterprise-Plan für 1 € möglich (Insufficient Server-Side Validation)

2. Fehlende Input-Validierung — negative Werte (money=-50) und Buchstaben akzeptiert, kein Typecheck

3. Reflected XSS (bestätigt) — <img src=x onerror=alert(1)> und <svg onload=alert(1)> lösten Alert aus; raw String-Concatenation ohne Output-Encoding, keine CSP

## Auf Admin.php (Login):

4. Credentials via GET (CWE-598) — Login sendet Email + Password per GET → in URL, Logs, History sichtbar

5. SQLi getestet, nicht bestätigt — error-based, boolean (OR '1'='1), time-based (SLEEP) durchprobiert, alle URL-encoded → negatives Ergebnis (gilt als valide Test-Coverage für den Report).

# Auf Kontaktformular (Support.php):

6. Unrestricted File Upload (CWE-434) — .php-Upload ohne Typvalidierung akzeptiert. Post-Upload-Response statisch, kein reflected XSS. Speicherort noch unklar.


## Findings

Finding X: Reflected Cross-Site Scripting (XSS)
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

---

Finding X: Business Logic Flaw — Client-Controlled Pricing
Severity: High

CVSS 3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N — 5.3 (Medium)

CWE: CWE-840 (Business Logic Errors)

(ergänzend: CWE-602 — Client-Side Enforcement of Server-Side Security; CWE-20 — Improper Input Validation)
Description:

The money parameter on Deals.php is accepted and processed without server-side validation. The price/amount is controlled entirely by the client and trusted by the server. An attacker can submit arbitrary values — including negative numbers and non-numeric input — which the application accepts without rejection. Security-relevant logic (price integrity) is enforced only on the client side, if at all, and can be bypassed by manipulating the request directly.
Affected Component:

http://10.10.10.10/Deals.php, parameter money
Proof of Concept:

Intercept the request to Deals.php and modify the money parameter. (Screenshot)
Submit a negative value (e.g. money=-100) → accepted by the application without error. (Screenshot)
Submit non-numeric input → accepted without validation. (Screenshot)

Impact:

The application accepts invalid and manipulated values (negative and non-numeric) for the money parameter without server-side validation and returns a success confirmation. This confirms missing server-side input validation and client-controlled handling of a security-relevant value. The downstream processing of the manipulated value (e.g. whether it results in an actual financial transaction, balance change, or stored corrupted data) could not be observed within the scope of this test. Depending on that processing, the flaw may enable financial manipulation or business data corruption. The absence of validation is confirmed; the full business impact requires verification against the application's backend logic.

