
http://10.10.10.10/visiter-newsdesk.php

?id=1%20UNION%20SELECT%201,column_name,3,4,5,6%20FROM%20information_schema.columns%20WHERE%20table_schema=%27TechNation%27%20AND%20table_name=%27Users%27--%20-

?id=1%20UNION%20SELECT%201,Admin,Password,Email,5,6%20FROM%20Users--%20-


## Table Schema
### Invocie
BillingAddress
BillingCity
BillingCounry
BillingPostalCode
BillingState
CustomerId
InvoiceDate
InvoiceId
Total

?id=1%20UNION%20SELECT%201,InvoiceDate,Total,CustomerId,5,6%20FROM%Invocie--%20-


## Findings

Finding X: SQL Injection (Unauthenticated)
Severity: Critical

CVSS 3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — 9.8

CWE: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)

(ergänzend: CWE-209 — Information Exposure Through Error Messages)
Description:

A query function accessible without authentication passes user input directly into a SQL statement without sanitization or parameterization. A single quote (') triggers a verbose database error; a boolean payload (' OR 1=1 -- ) alters the query logic. A UNION-based injection was confirmed (6 columns), allowing extraction of arbitrary database content. The application connects to the database using a fully privileged account, granting read and write access across the entire schema.
Affected Component:

http://10.10.10.10/[blog-seite], parameter [parametername]
Proof of Concept:

Access the query page without authentication. (Screenshot)
Submit ' → raw database error returned (confirms injectable input). (Screenshot)
Submit ' OR 1=1 --  → query logic bypassed. (Screenshot)
Determine column count via ORDER BY (6 columns) and confirm reflected columns via UNION SELECT. (Screenshot)
Disclose database metadata: MySQL 8.0.42, database TechNation, connecting user with full privileges. (Screenshot)
Enumerate schema — tables include users, customer, employee, invoice, invoiceline. The users table contains columns Email, First_Name, Last_Name, Password, and an Admin flag, confirming access to credentials and personal data. (Screenshot — column structure only; no record contents extracted)

Impact:

An unauthenticated attacker has full read and write access to the entire database, including customer records, employee data, invoices, and the users table containing credentials and personal data. This permits theft of personal and financial information, modification or deletion of records, and authentication bypass via credential extraction. As the personal data of customers and employees is affected, this constitutes a reportable data breach risk under GDPR. The privileged database account further raises the possibility of file system access on the host.
Remediation:

In [exact file/function], replace dynamic SQL with parameterized queries / prepared statements. Validate and type-check all input. Disable verbose database error messages in production. (See also the database privilege finding below.)



Finding Y: Database Connection Uses Over-Privileged Account
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