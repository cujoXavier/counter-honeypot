SSH Threat Detection 🔐
Detects brute-force attempts with weak credentials
Identifies default usernames (admin, root, postgres, etc.)
Recognizes weak passwords and keyboard patterns
Detects malicious SSH commands (rm -rf, reverse shells, etc.)
WEB Threat Detection 🌐
SQL Injection detection (UNION, DROP, INSERT, DELETE)
Cross-Site Scripting (XSS) detection (scripts, JavaScript events)
Path Traversal detection (../, /etc/passwd, etc.)
Reconnaissance tool identification (SQLmap, Nikto, Nmap, Burp)
Database Threat Detection 🗄️
Default credential exploitation (MySQL, PostgreSQL, MSSQL)
Empty password detection
Dangerous SQL patterns (xp_cmdshell, LOAD_FILE, etc.)

Multi-database support
Key Features:
✓ Threat severity classification (CRITICAL, HIGH, MEDIUM, LOW)
✓ Cryptographic threat hashing and logging
✓ Comprehensive threat reports with JSON output
✓ Demonstration simulations included
✓ Dual logging (file + console)

Run the demo with:

bash
python counter_honeypot_multi.py
This demonstrates the critical need to protect systems from threat actors exploiting SSH, WEB, and Database vulnerabilities
