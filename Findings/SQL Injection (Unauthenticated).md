# SQL Injection (Unauthenticated)
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
