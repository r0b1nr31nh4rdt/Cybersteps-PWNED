# Business Logic Flaw — Client-Controlled Pricing
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