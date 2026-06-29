# Database Connection Uses Over-Privileged Account
Severity: Medium

CVSS 3.1: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L — 5.0

CWE: CWE-250 (Execution with Unnecessary Privileges)

(ergänzend: CWE-269 — Improper Privilege Management)
Description:

The web application connects to the MySQL database using the debian-sys-maint account, a system maintenance account that holds full privileges (including GRANT and potentially FILE). This violates the principle of least privilege. The finding does not introduce a direct attack vector on its own; its severity stems from amplifying the impact of Finding X (SQL Injection): because the application connects with an all-privileged account, an otherwise limited injection escalates from read access to full database compromise — read, write, delete, and potentially host file system access.
Affected Component:

Database connection configuration of the application ([config file / connection string]).
Proof of Concept:

Via the SQL injection in Finding X, query the current database user: ' UNION SELECT 1,current_user(),3,4,5,6-- -. (Screenshot)
Result: debian-sys-maint@localhost, confirmed to hold all privileges. (Screenshot)

Impact:

Any injection or query-manipulation vulnerability inherits full administrative database privileges. This raises the impact of Finding X from data disclosure to complete database compromise (modification and deletion of records) and, via the FILE privilege, potential read/write access to the underlying host file system. On its own — without a second vulnerability to reach the database — this misconfiguration is not directly exploitable, which is reflected in the Medium rating.
Remediation:

Create a dedicated application database user with the minimum required privileges (typically SELECT, plus INSERT/UPDATE only on the specific tables the application requires). Never use debian-sys-maint or any administrative/system account for application connectivity. Remove FILE, GRANT, and DDL privileges from the application account. Verify with SHOW GRANTS FOR '<app_user>'@'<host>'; that only the intended privileges are present.