"""
Advanced Example: Custom Security Rules with Kavach MCP

This example shows how to extend Kavach with custom security rules
for your specific use case.
"""

import re
from kavach import KavachMiddleware
from kavach.types import Rule
from typing import List

def create_custom_middleware() -> KavachMiddleware:
    """
    Create a middleware with custom security rules
    """
    
    # Define custom rules - focused on specific patterns
    custom_rules = [
        Rule(
            id="dangerous-eval",
            name="Dangerous Eval/Exec Detection",
            description="Detects usage of dangerous functions like eval() and exec()",
            severity="critical",
            patterns=[re.compile(r"\b(eval|exec|compile)\s*\(", re.IGNORECASE)]
        ),
        Rule(
            id="sql-injection-keywords",
            name="SQL Injection Patterns",
            description="Detects SQL injection attempts with dangerous keywords",
            severity="high",
            patterns=[re.compile(r"(DROP\s+TABLE|DELETE\s+FROM|UNION\s+SELECT|';|--\s|\/\*)", re.IGNORECASE)]
        ),
        Rule(
            id="file-traversal",
            name="Path Traversal Attempts",
            description="Detects directory traversal attempts using ../ or ..\\",
            severity="high",
            patterns=[re.compile(r"(\.\./|\.\.\\)")]
        ),
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
        result = middleware.process(test['call'])
        
        status = "✅ ALLOWED" if result.get('allowed') else "❌ BLOCKED"
        print(f"Expected: {test['expected']}")
        print(f"Actual:   {status}")
        
        if not result.get('allowed'):
            violations = result.get('violations', [])
            if violations:
                print(f"Violations:")
                for violation in violations:
                    print(f"  - {violation.get('name')} (Severity: {violation.get('severity')})")
        
        print()
    
    print("=" * 80)
    print("Advanced Example Complete!")
    print("=" * 80)

if __name__ == "__main__":
    main()
