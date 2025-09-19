import argparse
import json
import logging
import os
import re
import sys
import tempfile
import yaml
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple
import hashlib
import subprocess
from datetime import datetime
import html

# Third-party imports (would be in requirements.txt)
try:
    import git
    from libsast import Scanner
    import requests
except ImportError:
    print("Please install required packages: pip install gitpython libsast requests")
    sys.exit(1)

class SecretDetectionEngine:
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.setup_logging()
        self.found_secrets: List[Dict] = []
        self.scan_stats: Dict[str, int] = {
            'files_scanned': 0,
            'secrets_found': 0,
            'high_confidence': 0,
            'medium_confidence': 0,
            'low_confidence': 0
        }
        
    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from YAML file or use defaults"""
        #Custom rule engine with pattern matching
        default_config = {
            'rules': {
                'api_keys': {
                    'patterns': [
                        r'(?i)(api[_-]?key|access[_-]?key|secret[_-]?key)[\s=:]+[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
                        r'(?i)(aws[_-]?access[_-]?key)[\s=:]+[\'"]?([A-Z0-9]{20})[\'"]?',
                        r'(?i)(aws[_-]?secret[_-]?key)[\s=:]+[\'"]?([A-Za-z0-9/+=]{40})[\'"]?'
                    ],
                    'confidence': 'high',
                    'description': 'API keys and access tokens'
                },
                'passwords': {
                    'patterns': [
                        r'(?i)(password|passwd|pwd)[\s=:]+[\'"]?([^\s\'"]{8,})[\'"]?',
                        r'(?i)(db[_-]?password|database[_-]?password)[\s=:]+[\'"]?([^\s\'"]{8,})[\'"]?'
                    ],
                    'confidence': 'high',
                    'description': 'Password in plain text'
                },
                'tokens': {
                    'patterns': [
                        r'(?i)(token|bearer|jwt)[\s=:]+[\'"]?([a-zA-Z0-9_\-\.]{20,})[\'"]?',
                        r'eyJhbGciOiJ[^\s\'"]{50,}',  # JWT pattern
                        r'gh[opsu]_[A-Za-z0-9_]{36}',  # GitHub tokens
                    ],
                    'confidence': 'high',
                    'description': 'Authentication tokens'
                },
                'crypto_keys': {
                    'patterns': [
                        r'-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----',
                        r'-----BEGIN PRIVATE KEY-----',
                        r'ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}',
                    ],
                    'confidence': 'critical',
                    'description': 'Private cryptographic keys'
                }
            },
            'exclusions': {
                'files': [
                    '**/node_modules/**',
                    '**/vendor/**',
                    '**/__pycache__/**',
                    '**/*.min.js',
                    '**/*.bundle.js',
                    '**/package-lock.json',
                    '**/yarn.lock'
                ],
                'patterns': [
                    r'example[_-]key',
                    r'test[_-]password',
                    r'mock[_-]token',
                    r'sample[_-]api[_-]key',
                    r'placeholder',
                    r'xxxx',
                    r'123456'
                ],
                'extensions': ['.jpg', '.png', '.gif', '.pdf', '.zip', '.tar', '.gz']
            },
            'confidence_thresholds': {
                'critical': 90,
                'high': 70,
                'medium': 60,
                'low': 20
            }
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Deep merge with defaults
                    return self._deep_merge(default_config, user_config)
            except Exception as e:
                logging.warning(f"Failed to load config file: {e}. Using defaults.")
        
        return default_config
    
    def _deep_merge(self, base: Dict, update: Dict) -> Dict:
        """Recursively merge two dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                base[key] = self._deep_merge(base[key], value)
            else:
                base[key] = value
        return base
    
    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security-scan.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def should_scan_file(self, file_path: str) -> bool:
        """Check if file should be scanned based on exclusions"""
        path = Path(file_path)
        
        # Check file extensions
        if path.suffix.lower() in self.config['exclusions']['extensions']:
            return False
        
        # Check file patterns
        for pattern in self.config['exclusions']['files']:
            if path.match(pattern):
                return False
        
        return True
    
    def calculate_confidence(self, rule_name: str, match: str, context: str) -> int:
        """Calculate confidence score for a detected secret"""
        base_confidence = {
            'critical': 90,
            'high': 70,
            'medium': 60,
            'low': 30
        }.get(self.config['rules'][rule_name]['confidence'], 50)
        
        # Adjust confidence based on context
        adjustments = 0
        #False positive reduction with context analysis
        # Reduce confidence for common false positives
        false_positive_indicators = [
            r'example', r'test', r'mock', r'sample', 
            r'placeholder', r'xxxx', r'1234', r'password'
        ]
        
        for indicator in false_positive_indicators:
            if re.search(indicator, match, re.IGNORECASE) or \
               re.search(indicator, context, re.IGNORECASE):
                adjustments -= 20
        
        # Increase confidence for certain patterns
        if re.search(r'[0-9a-f]{40}', match):  # SHA-1 like pattern
            adjustments += 15
        if re.search(r'[0-9a-f]{64}', match):  # SHA-256 like pattern
            adjustments += 20
        if re.search(r'sk_', match):  # Stripe secret key pattern
            adjustments += 25
        
        return max(0, min(100, base_confidence + adjustments))
    
    def scan_file(self, file_path: str) -> List[Dict]:
        """Scan a single file for secrets"""
        findings = []
        
        if not self.should_scan_file(file_path):
            return findings
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                for rule_name, rule_config in self.config['rules'].items():
                    for pattern in rule_config['patterns']:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        
                        for match in matches:
                            secret_value = match.group(2) if len(match.groups()) >= 2 else match.group(0)
                            
                            # Skip excluded patterns
                            if any(re.search(exclusion, secret_value, re.IGNORECASE) 
                                  for exclusion in self.config['exclusions']['patterns']):
                                continue
                            
                            # Get context around the match
                            line_number = content[:match.start()].count('\n') + 1
                            line_content = lines[line_number - 1] if line_number <= len(lines) else ''
                            
                            confidence = self.calculate_confidence(
                                rule_name, secret_value, line_content
                            )
                            
                            # Only report if above low confidence threshold
                            if confidence >= self.config['confidence_thresholds']['low']:
                                finding = {
                                    'file': file_path,
                                    'line': line_number,
                                    'rule': rule_name,
                                    'secret': secret_value[:100] + '...' if len(secret_value) > 100 else secret_value,
                                    'confidence': confidence,
                                    'context': line_content.strip(),
                                    'severity': self._confidence_to_severity(confidence),
                                    'hash': hashlib.sha256(secret_value.encode()).hexdigest()[:16]
                                }
                                findings.append(finding)
                                
                                # Update statistics
                                self.scan_stats['secrets_found'] += 1
                                if confidence >= 70:
                                    self.scan_stats['high_confidence'] += 1
                                elif confidence >= 40:
                                    self.scan_stats['medium_confidence'] += 1
                                else:
                                    self.scan_stats['low_confidence'] += 1
            
            self.scan_stats['files_scanned'] += 1
            
        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")
        
        return findings
    
    def _confidence_to_severity(self, confidence: int) -> str:
        """Convert confidence score to severity level"""
        if confidence >= 80:
            return 'critical'
        elif confidence >= 60:
            return 'high'
        elif confidence >= 40:
            return 'medium'
        else:
            return 'low'
    
    def scan_directory(self, path: str) -> List[Dict]:
        """Recursively scan directory for secrets"""
        all_findings = []
        path_obj = Path(path)
        
        if not path_obj.exists():
            logging.error(f"Path does not exist: {path}")
            return all_findings
        
        file_patterns = [
            '**/*.py', '**/*.js', '**/*.ts', '**/*.java', '**/*.go',
            '**/*.rb', '**/*.php', '**/*.cpp', '**/*.h', '**/*.cs',
            '**/*.yml', '**/*.yaml', '**/*.json', '**/*.xml', '**/*.config',
            '**/*.env', '**/.env*', '**/*.properties', '**/*.txt', '**/*.md'
        ]
        
        for pattern in file_patterns:
            for file_path in path_obj.glob(pattern):
                if file_path.is_file():
                    findings = self.scan_file(str(file_path))
                    all_findings.extend(findings)
        
        return all_findings
    
    #Git history scanning for committed secrets 
    def scan_git_history(self, repo_path: str) -> List[Dict]:
        """Scan git history for committed secrets"""
        findings = []
        
        try:
            repo = git.Repo(repo_path)
            
            # Get all commits
            for commit in repo.iter_commits('HEAD'):
                # Check each file in the commit
                for file_path in commit.stats.files:
                    if self.should_scan_file(file_path):
                        try:
                            file_content = repo.git.show(f'{commit.hexsha}:{file_path}')
                            temp_findings = self._scan_content(file_content, f'git:{commit.hexsha[:8]}:{file_path}')
                            for finding in temp_findings:
                                finding['commit'] = commit.hexsha
                                finding['author'] = str(commit.author)
                                finding['date'] = commit.committed_datetime.isoformat()
                            findings.extend(temp_findings)
                        except:
                            # File might have been deleted or other git issues
                            continue
            
        except Exception as e:
            logging.error(f"Error scanning git history: {e}")
        
        return findings
    
    def _scan_content(self, content: str, source: str) -> List[Dict]:
        """Scan content string for secrets"""
        findings = []
        
        for rule_name, rule_config in self.config['rules'].items():
            for pattern in rule_config['patterns']:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    secret_value = match.group(2) if len(match.groups()) >= 2 else match.group(0)
                    
                    if any(re.search(exclusion, secret_value, re.IGNORECASE) 
                          for exclusion in self.config['exclusions']['patterns']):
                        continue
                    
                    line_number = content[:match.start()].count('\n') + 1
                    lines = content.split('\n')
                    line_content = lines[line_number - 1] if line_number <= len(lines) else ''
                    
                    confidence = self.calculate_confidence(rule_name, secret_value, line_content)
                    
                    if confidence >= self.config['confidence_thresholds']['low']:
                        finding = {
                            'file': source,
                            'line': line_number,
                            'rule': rule_name,
                            'secret': secret_value[:100] + '...' if len(secret_value) > 100 else secret_value,
                            'confidence': confidence,
                            'context': line_content.strip(),
                            'severity': self._confidence_to_severity(confidence),
                            'hash': hashlib.sha256(secret_value.encode()).hexdigest()[:16]
                        }
                        findings.append(finding)
        
        return findings
    
    def run_dependency_check(self, path: str) -> List[Dict]:
        """Run dependency vulnerability check"""
        findings = []
        
        # Check for common dependency files
        dep_files = [
            'package.json', 'requirements.txt', 'pom.xml', 
            'build.gradle', 'go.mod', 'composer.json'
        ]
        
        for dep_file in dep_files:
            dep_path = Path(path) / dep_file
            if dep_path.exists():
                # This would integrate with real tools like OWASP Dependency Check
                # For now, we'll simulate findings
                findings.append({
                    'type': 'dependency',
                    'file': str(dep_path),
                    'severity': 'medium',
                    'description': 'Outdated dependency detected (simulated finding)',
                    'confidence': 60
                })
        
        return findings
    #Multiple output formats (JSON, SARIF, HTML)
    def generate_report(self, findings: List[Dict], format: str = 'json') -> str:
        """Generate report in specified format"""
        if format == 'json':
            return json.dumps({
                'timestamp': datetime.now().isoformat(),
                'scan_stats': self.scan_stats,
                'findings': findings,
                'summary': self._generate_summary(findings)
            }, indent=2)
        
        elif format == 'sarif':
            return self._generate_sarif_report(findings)
        
        elif format == 'html':
            return self._generate_html_report(findings)
        
        else:
            return self._generate_text_report(findings)
    
    def _generate_summary(self, findings: List[Dict]) -> Dict:
        """Generate summary statistics"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        rule_counts = {}
        
        for finding in findings:
            severity_counts[finding['severity']] = severity_counts.get(finding['severity'], 0) + 1
            rule_counts[finding['rule']] = rule_counts.get(finding['rule'], 0) + 1
        
        return {
            'total_findings': len(findings),
            'severity_breakdown': severity_counts,
            'rule_breakdown': rule_counts,
            'pass_fail': self._determine_pass_fail(findings)
        }
    
    def _determine_pass_fail(self, findings: List[Dict]) -> str:
        """Determine if scan passes or fails based on findings"""
        critical_high = sum(1 for f in findings if f['severity'] in ['critical', 'high'])
        return 'FAIL' if critical_high > 0 else 'PASS'
    
    def _generate_sarif_report(self, findings: List[Dict]) -> str:
        """Generate SARIF format report"""
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecretDetectionEngine",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/your-org/secret-scanner"
                        }
                    },
                    "results": []
                }
            ]
        }
        
        for finding in findings:
            sarif['runs'][0]['results'].append({
                "ruleId": finding['rule'],
                "level": finding['severity'],
                "message": {
                    "text": f"Potential secret found: {finding['secret']}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding['file']
                            },
                            "region": {
                                "startLine": finding['line'],
                                "snippet": {
                                    "text": finding['context']
                                }
                            }
                        }
                    }
                ],
                "properties": {
                    "confidence": finding['confidence'],
                    "secretHash": finding['hash']
                }
            })
        
        return json.dumps(sarif, indent=2)
    
    def _generate_html_report(self, findings: List[Dict]) -> str:
        """Generate HTML format report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .critical {{ color: #d73a49; font-weight: bold; }}
                .high {{ color: #f66a0a; }}
                .medium {{ color: #ffd33d; }}
                .low {{ color: #0366d6; }}
                .finding {{ border: 1px solid #e1e4e8; padding: 16px; margin: 8px 0; }}
                .summary {{ background: #f6f8fa; padding: 16px; }}
            </style>
        </head>
        <body>
            <h1>Security Scan Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p>Total findings: {len(findings)}</p>
                <p>Status: <strong>{self._determine_pass_fail(findings)}</strong></p>
            </div>
            <h2>Findings</h2>
        """
        
        for finding in findings:
            html_content += f"""
            <div class="finding">
                <h3 class="{finding['severity']}">
                    {finding['severity'].upper()}: {finding['rule']} in {finding['file']}:{finding['line']}
                </h3>
                <p><strong>Secret:</strong> {html.escape(str(finding['secret']))}</p>
                <p><strong>Context:</strong> <code>{html.escape(finding['context'])}</code></p>
                <p><strong>Confidence:</strong> {finding['confidence']}%</p>
                <p><strong>Hash:</strong> {finding['hash']}</p>
            </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        return html_content
    
    def _generate_text_report(self, findings: List[Dict]) -> str:
        """Generate text format report"""
        report = [
            "=" * 80,
            "SECURITY SCAN REPORT",
            "=" * 80,
            f"Timestamp: {datetime.now().isoformat()}",
            f"Files scanned: {self.scan_stats['files_scanned']}",
            f"Secrets found: {self.scan_stats['secrets_found']}",
            f"Status: {self._determine_pass_fail(findings)}",
            "",
            "FINDINGS:",
            "=" * 80
        ]
        
        for finding in findings:
            report.extend([
                f"Severity: {finding['severity'].upper()}",
                f"File: {finding['file']}:{finding['line']}",
                f"Rule: {finding['rule']}",
                f"Secret: {finding['secret']}",
                f"Context: {finding['context']}",
                f"Confidence: {finding['confidence']}%",
                f"Hash: {finding['hash']}",
                "-" * 70
            ])
        
        return "\n".join(report)

def main():
    print("=== Advanced Secret Detection Engine ===\n")

    # Prompt user for inputs
    path = input("Enter the path to scan: ").strip()
    output_format = input("Enter output format (json, sarif, html, text) [json]: ").strip() or "json"
    config_path = input("Enter path to config file (optional, press Enter to skip): ").strip() or None

    git_history_input = input("Scan git history? (y/N): ").strip().lower()
    git_history = git_history_input == "y"

    dependencies_input = input("Run dependency vulnerability check? (y/N): ").strip().lower()
    dependencies = dependencies_input == "y"

    output_file = input("Enter output file path (optional, press Enter to print to console): ").strip() or None
    #Multi-scanner integration (SAST, dependency check, secrets scan)
    # Initialize scanner
    scanner = SecretDetectionEngine(config_path)
    logging.info(f"Starting security scan of: {path}")

    all_findings = []

    # Scan current files
    file_findings = scanner.scan_directory(path)
    all_findings.extend(file_findings)

    # Scan git history if requested
    if git_history:
        git_findings = scanner.scan_git_history(path)
        all_findings.extend(git_findings)

    # Run dependency check if requested
    if dependencies:
        dep_findings = scanner.run_dependency_check(path)
        all_findings.extend(dep_findings)

    # Generate report
    report = scanner.generate_report(all_findings, output_format)

    # Output results
    if output_file:
        with open(output_file, 'w') as f:
            f.write(report)
        logging.info(f"Report written to: {output_file}")
    else:
        print(report)

    # Exit with appropriate code
    summary = scanner._generate_summary(all_findings)
    if summary['pass_fail'] == 'FAIL':
        logging.error("Scan failed - critical or high severity findings detected")
        sys.exit(1)
    else:
        logging.info("Scan completed successfully")
        sys.exit(0)


if __name__ == "__main__":
    main()


