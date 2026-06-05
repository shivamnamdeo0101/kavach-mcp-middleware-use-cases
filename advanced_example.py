"""
╔════════════════════════════════════════════════════════════════════════════════╗
║               CUSTOM SECURITY RULES: EXTEND KAVACH FOR YOUR DOMAIN             ║
║                                                                                ║
║  PURPOSE: Create custom Rule objects to detect threats specific to your app   ║
║                                                                                ║
║  HOW IT WORKS:                                                                 ║
║  1. Define Rule with: id, name, description, severity, patterns (regex)      ║
║  2. Pass custom_rules to KavachMiddleware()                                   ║
║  3. Kavach scans tool calls against BOTH default + custom rules               ║
║                                                                                ║
║  EXAMPLE CUSTOM RULES:                                                         ║
║  • Detect company secrets: "PROJECT_CODENAME", "INTERNAL_API_KEY"            ║
║  • Detect dangerous functions: eval(), exec(), system()                       ║
║  • Detect SQL keywords: DROP, DELETE, TRUNCATE                                ║
║  • Detect shell patterns: |, &&, ;, pipe chains                               ║
║                                                                                ║
║  SEVERITY LEVELS:                                                              ║
║  critical - Stop immediately (e.g., malware, data deletion)                   ║
║  high     - Block but log (e.g., SQL injection, path traversal)               ║
║  medium   - Alert (e.g., unusual access patterns)                             ║
║  low      - Log (e.g., suspicious but benign)                                 ║
║                                                                                ║
╚════════════════════════════════════════════════════════════════════════════════╝
"""

import re
from kavach import KavachMiddleware
from kavach.types import Rule
from kavach.middleware import SecurityException
from typing import List

def create_custom_middleware() -> KavachMiddleware:
    """
    Create a middleware with custom security rules
    """
    
    # Define custom rules - focused on specific patterns
    custom_rules = [
        # RULE 1: Dangerous Eval/Exec Detection
        # Detects: eval(), exec(), compile() - Python code execution functions
        # Severity: CRITICAL (can execute arbitrary code)
        # Example attack: eval(user_input) → attacker runs arbitrary Python
        Rule(
            id="dangerous-eval",
            name="Dangerous Eval/Exec Detection",
            description="Detects usage of dangerous functions like eval() and exec()",
            severity="critical",
            patterns=[re.compile(r"\b(eval|exec|compile)\s*\(", re.IGNORECASE)]
        ),
        
        # RULE 2: SQL Injection Keywords
        # Detects: DROP TABLE, DELETE FROM, UNION SELECT, etc.
        # Severity: HIGH (data loss/corruption/exfiltration)
        # Example attack: "SELECT * FROM users; DROP TABLE users;--"
        Rule(
            id="sql-injection-keywords",
            name="SQL Injection Patterns",
            description="Detects SQL injection attempts with dangerous keywords",
            severity="high",
            patterns=[re.compile(r"(DROP\s+TABLE|DELETE\s+FROM|UNION\s+SELECT|';|--\s|\/\*)", re.IGNORECASE)]
        ),
        
        # RULE 3: Path Traversal
        # Detects: ../ or ..\ (directory up patterns)
        # Severity: HIGH (unauthorized file access)
        # Example attack: "../../etc/passwd" to access system files
        Rule(
            id="file-traversal",
            name="Path Traversal Attempts",
            description="Detects directory traversal attempts using ../ or ..\\",
            severity="high",
            patterns=[re.compile(r"(\.\./|\.\.\\)")]
        ),
        
        # RULE 4: Destructive Shell Commands
        # Detects: Piping destructive commands (rm, del, truncate, format)
        # Severity: HIGH (permanent data loss)
        # Example attack: "find /tmp | rm -rf /" or "ls | del C:\*.*"
        Rule(
            id="dangerous-shell-pipe",
            name="Shell Command Piping",
            description="Detects dangerous shell command piping patterns",
            severity="high",
            patterns=[re.compile(r"(?:^|\s)(?:\||\|\||&&)\s*(?:rm|del|drop|truncate|format)", re.IGNORECASE)]
        ),
    ]
    
    return KavachMiddleware(rules=custom_rules, strict=True)

def main():
    print("=" * 80)
    print("Kavach MCP - Advanced Custom Rules Example")
    print("=" * 80)
    print()
    
    middleware = create_custom_middleware()
    
    test_cases = [
        {
            "name": "Normal API Call",
            "call": {
                "tool": "api.fetch",
                "url": "https://api.example.com/users",
                "method": "GET"
            },
            "expected": "✅ ALLOWED"
        },
        {
            "name": "Dangerous Eval",
            "call": {
                "tool": "code.execute",
                "code": "eval(user_input)"
            },
            "expected": "❌ BLOCKED"
        },
        {
            "name": "SQL Injection Attempt",
            "call": {
                "tool": "database.query",
                "query": "SELECT * FROM users WHERE id = 1; DROP TABLE users;"
            },
            "expected": "❌ BLOCKED"
        },
        {
            "name": "SQL UNION Attack",
            "call": {
                "tool": "database.query",
                "query": "SELECT * FROM users UNION SELECT * FROM passwords"
            },
            "expected": "❌ BLOCKED"
        },
        {
            "name": "Path Traversal",
            "call": {
                "tool": "file.read",
                "path": "../../etc/passwd"
            },
            "expected": "❌ BLOCKED"
        },
        {
            "name": "Dangerous Shell Pipe",
            "call": {
                "tool": "system.execute",
                "command": "find /tmp | rm -rf /"
            },
            "expected": "❌ BLOCKED"
        },
        {
            "name": "Safe Database Query",
            "call": {
                "tool": "database.query",
                "query": "SELECT * FROM users WHERE email = ?",
                "params": ["user@example.com"]
            },
            "expected": "✅ ALLOWED"
        },
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"Test {i}: {test['name']}")
        print("-" * 80)
        status = "✅ ALLOWED"
        violation_details = None
        try:
            result = middleware.process(test['call'])
        except SecurityException as e:
            status = "❌ BLOCKED"
            error_msg = str(e)
            if "Violations:" in error_msg:
                violations_str = error_msg.split("Violations: ")[1]
                import ast
                violation_details = ast.literal_eval(violations_str)
        
        print(f"Expected: {test['expected']}")
        print(f"Actual:   {status}")
        
        if violation_details:
            print(f"Violations:")
            for violation in violation_details:
                print(f"  - {violation.get('name')} (Severity: {violation.get('severity')})")
        
        print()
    
    print("=" * 80)
    print("Advanced Example Complete!")
    print("=" * 80)

if __name__ == "__main__":
    main()
