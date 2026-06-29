Finding X: Directory Listing Enabled
Severity: Low

CVSS 3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — 5.3

CWE: CWE-548 (Exposure of Information Through Directory Listing)
Description:

The web server returns a full directory listing for /icon/ when the directory is requested without a specific file. With no index file present and directory listing enabled in the web server configuration, the contents of the directory — including all stored files and their last-modified timestamps — are disclosed to any unauthenticated visitor.
Affected Component:

http://10.10.10.10/icon/
Proof of Concept:

Request the directory directly in a browser: http://10.10.10.10/icon/. (Screenshot)
The server responds with an auto-generated index listing the directory's files and modification dates. (Screenshot)

Impact:

Directory listings disclose the names, types, and timestamps of files that are not intended to be browsed directly. While only image files were observed in this directory, the exposure aids reconnaissance: an attacker can map application assets, infer naming conventions, and discover files that would otherwise remain hidden. In directories holding sensitive content, this can directly expose confidential files.
Remediation:

Disable automatic directory listing in the web server configuration (Apache: Options -Indexes). Place an index file in each directory as defense-in-depth. Ensure sensitive files are stored outside web-accessible paths regardless of listing configuration.