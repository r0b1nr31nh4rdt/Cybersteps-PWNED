# Hidden Sites

## Free reachable hidden sites
- http://10.10.10.10/exercises/
- http://10.10.10.10/dashboard/
- http://10.10.10.10/topsecret.html
- http://10.10.10.10/EmployeeHandbook.php
- http://10.10.10.10/ThemeLoader.php/
- http://10.10.10.10/visiter-newsdesk.php
- http://10.10.10.10/Editor/


## Findings
Finding X: Broken Access Control via Forced Browsing
Severity: High

CVSS 3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — 7.5

CWE: CWE-306 (Missing Authentication for Critical Function)

(ergänzend: OWASP A01:2021 – Broken Access Control)
Description:

Multiple sensitive resources are accessible by directly requesting their URL, without any authentication or authorization check. These resources are not referenced in the application's navigation; the only barrier protecting them is the absence of a link ("security by obscurity"), which provides no actual access control. Any unauthenticated user who knows or guesses the path gains direct access.
Affected Component:

http://10.10.10.10/[template-seite] (template editing functionality)
http://10.10.10.10/[datei-seite] (file disclosure)

(weitere betroffene Pfade hier listen)

Proof of Concept:

The resources are not linked anywhere in the application UI.
Request the URL directly in the browser: http://10.10.10.10/[pfad]
The page loads and exposes its functionality without prompting for authentication or checking authorization. (Screenshot)
Repeat for each affected endpoint. (Screenshots)

Impact:

Sensitive functionality and data are exposed to unauthenticated users. The lack of access control allows anyone to reach administrative and data-handling features that should be restricted to authorized roles. The specific technical consequences of each exposed endpoint are documented in their respective findings (siehe Finding Y, Z).
Remediation:

Enforce server-side authentication and authorization on every endpoint, regardless of whether it is linked in the UI. Apply a deny-by-default access control policy: every request must be explicitly authorized before the resource is served. Do not rely on unlinked/obscure paths as a protection mechanism.