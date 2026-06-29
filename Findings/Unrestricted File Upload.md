# Unrestricted File Upload
Severity: High

CVSS 3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N — 5.4

CWE: CWE-434 (Unrestricted Upload of File with Dangerous Type)
Description:

The file upload function on support.php accepts files without server-side validation of file type, extension, or content. Files with dangerous extensions — including .php — are accepted without any error or rejection. The application does not restrict uploads to an allowlist of safe types. Whether uploaded files are stored in a web-accessible directory and executed by the server could not be confirmed within the scope of this test.
Affected Component:

http://10.10.10.10/support.php (file upload field)
Proof of Concept:

Access the upload form on support.php. (Screenshot)
Upload a file with a .php extension. (Screenshot)
The file is accepted without any type validation or error message. (Screenshot)

Impact:

The lack of file type validation allows an attacker to upload arbitrary file types, including server-side scripts (.php). If the upload directory is web-accessible and the server executes PHP files, this would enable remote code execution and full server compromise — the typical worst-case outcome of this vulnerability class. This escalation path was not verified during testing (the storage location and execution behaviour could not be determined), but the absence of any upload restriction is confirmed and represents a serious risk that warrants immediate remediation.
Remediation:

In the code handling support.php, validate uploads server-side against a strict allowlist of permitted file types (by extension and MIME type and content inspection / magic bytes). Reject executable and script extensions (.php, .phtml, .php5, etc.). Store uploaded files outside the web root, or in a directory configured to never execute scripts (e.g. via web server config disabling PHP handling for that path). Rename uploaded files to randomized identifiers and strip original extensions. Enforce a maximum file size.