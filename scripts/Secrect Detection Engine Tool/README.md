The script is an Advanced Secret Detection Engine that scans source code and repositories for hardcoded secrets, vulnerable dependencies, and potential security issues. It’s designed for DevSecOps integration and CI/CD pipelines.
Key Features:
1. Detects API keys, passwords, tokens, and private cryptographic keys.
2. Generates JSON, SARIF, HTML, or plain text reports.
Workflow:
    * User specifies a path to scan and optional parameters.
    * Script scans all relevant files in the directory.
    * Optional Git history and dependency checks are performed.
    * Detected secrets are filtered, scored, and summarized.
    * Report is generated and output to a file or printed.
    * Exit code indicates success (0) or failure (1) based on high/critical findings.
Test Case 1:
=== Advanced Secret Detection Engine ===

Enter the path to scan: C:\Users\f501392\devsecops-assessment-siphesihle-mahlangu\country-flags-app-main\src\pages
Enter output format (json, sarif, html, text) [json]: text
Enter path to config file (optional, press Enter to skip): 
Scan git history? (y/N): y
Run dependency vulnerability check? (y/N): y
Enter output file path (optional, press Enter to print to console): 
2025-09-19 01:37:23,208 - INFO - Starting security scan of: C:\Users\f501392\devsecops-assessment-siphesihle-mahlangu\country-flags-app-main\src\pages      
2025-09-19 01:37:23,324 - ERROR - Error scanning git history: C:\Users\f501392\devsecops-assessment-siphesihle-mahlangu\country-flags-app-main\src\pages
================================================================================
SECURITY SCAN REPORT
================================================================================
Timestamp: 2025-09-19T01:37:23.324633
Files scanned: 2
Secrets found: 0
Status: PASS

FINDINGS:
================================================================================
2025-09-19 01:37:23,324 - INFO - Scan completed successfully
PS C:\Users\f501392\devsecops-assessment-siphesihle-mahlangu> ^C
PS C:\Users\f501392\devsecops-assessment-siphesihle-mahlangu>
PS C:\Users\f501392\devsecops-assessment-siphesihle-mahlangu>  c:; cd 'c:\Users\f501392\devsecops-assessment-siphesihle-mahlangu'; & 'c:\Users\f501392\AppData\Local\Programs\Python\Python312\python.exe' 'c:\Users\f501392\.vscode\extensions\ms-python.debugpy-2025.10.0-win32-x64\bundled\libs\debugpy\launcher' '52313' '--' 'C:\Users\f501392\devsecops-assessment-siphesihle-mahlangu\scripts\Secrect Detection Engine Tool\secretDector.py' 

test case 2:
=== Advanced Secret Detection Engine ===

Enter the path to scan: C:\Users\f501392\devsecops-assessment-siphesihle-mahlangu\country-service-main\src\test
Enter output format (json, sarif, html, text) [json]: text
Enter path to config file (optional, press Enter to skip):
Scan git history? (y/N): y
Run dependency vulnerability check? (y/N): y
Enter output file path (optional, press Enter to print to console):
2025-09-19 01:39:51,650 - INFO - Starting security scan of: C:\Users\f501392\devsecops-assessment-siphesihle-mahlangu\country-service-main\src\test
2025-09-19 01:39:51,742 - ERROR - Error scanning git history: C:\Users\f501392\devsecops-assessment-siphesihle-mahlangu\country-service-main\src\test
================================================================================
SECURITY SCAN REPORT
================================================================================
Timestamp: 2025-09-19T01:39:51.743095
Files scanned: 4
Secrets found: 1
Status: PASS

FINDINGS:
================================================================================
Severity: MEDIUM
File: C:\Users\f501392\devsecops-assessment-siphesihle-mahlangu\country-service-main\src\test\resources\application.properties:4
Rule: passwords
Secret: password
Context: spring.datasource.password=password
Confidence: 50%
Hash: 5e884898da280471
----------------------------------------
2025-09-19 01:39:51,744 - INFO - Scan completed successfully