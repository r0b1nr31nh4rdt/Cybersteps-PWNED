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