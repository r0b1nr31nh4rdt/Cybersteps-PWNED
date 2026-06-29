# Path Traversal / Arbitrary File Read
Severity: High

CVSS 3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — 7.5

CWE: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
Description:

The template functionality at [endpoint] accepts a user-controlled file path and returns the contents of the referenced file without validation or path restriction. By supplying absolute paths, an attacker can read arbitrary files on the server that are accessible to the web server process, outside the intended directory.
Affected Component:

http://10.10.10.10/[template-seite], parameter [parametername]
Proof of Concept:

Access the template page: http://10.10.10.10/[pfad]
Supply a local file path, e.g. /etc/passwd (Screenshot)
The application returns the raw file contents, disclosing local system user accounts.
Repeated successfully with /etc/hosts and /etc/apache2/apache2.conf, disclosing network configuration and web server configuration. (Screenshots)

Impact:

An attacker can read arbitrary files readable by the web server process. The disclosed files reveal system user accounts (/etc/passwd), internal host mappings (/etc/hosts), and the web server configuration (apache2.conf), which expose paths, virtual hosts, and module setup. This information can be leveraged to identify further sensitive files (configuration files, credentials, private keys, application source code) and to plan follow-up attacks.
Remediation:

In [exact file/function], do not pass user-supplied input directly to file-reading functions. Map a fixed identifier to an allowlisted server-side path instead of accepting raw paths. Reject input containing path traversal sequences (../), absolute paths, and null bytes. Apply least-privilege file system permissions to the web server process and restrict accessible directories (e.g. open_basedir).