# Kavach MCP Security Middleware - Simple Project

A demonstration project for using **Kavach**, a security middleware for Model Context Protocol (MCP) that detects and blocks malicious tool calls.

## 📋 Overview

This project shows how to integrate Kavach into your MCP-based applications to protect against:
- **Prompt Injection Attacks** - Detecting attempts to override instructions
- **Secret Leakage** - Identifying exposed AWS keys, OpenAI API keys
- **PII Exposure** - Detecting personal identifiable information patterns
- **Malicious Tool Calls** - Blocking suspicious or dangerous operations

## 🚀 Quick Start

### 1. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Demo

```bash
python main.py
```

## 📁 Project Structure

```
kavach-mcp-use-case/
├── main.py              # Demo application with test cases
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## 🔍 What the Demo Shows

The `main.py` script demonstrates 6 test cases:

1. **Safe Tool Call** - Normal, legitimate operation (allowed)
2. **Prompt Injection** - Attempt to override system instructions (blocked in strict mode)
3. **AWS Key Exposure** - Hardcoded AWS credentials (blocked)
4. **PII Detection** - Phone number detection (blocked)
5. **OpenAI Key Leakage** - Exposed API key (blocked)
6. **Non-strict Mode** - Same injection with lenient enforcement (allowed but reported)

## 💡 Usage Examples

### Basic Usage with Strict Mode (Default)

```python
from kavach import KavachMiddleware

# Strict mode = blocks any violations
middleware = KavachMiddleware(strict=True)

result = middleware.process({
    "tool": "aws.s3",
    "access_key": "AKIAIOSFODNN7EXAMPLE"
})

print(result)  # {"allowed": False, "violations": [...]}
```

### Lenient Mode (Report but Allow)

```python
# Lenient mode = allows but reports violations
middleware = KavachMiddleware(strict=False)

result = middleware.process({
    "tool": "ai.generate",
    "prompt": "ignore previous instructions"
})

print(result)  # {"allowed": True, "violations": [...]}
```

## 🛡️ Detected Patterns

Kavach detects:

- **Prompt Injection**: "ignore previous instructions", "override instructions", "disregard rules"
- **AWS Keys**: Patterns starting with `AKIA`
- **OpenAI Keys**: Patterns starting with `sk-`
- **PII**: 10-16 digit sequences (phone numbers, credit cards, etc.)

## 📚 Learn More

- **PyPI Package**: https://pypi.org/project/kavach-mcp/
- **GitHub**: The package page on PyPI has links to the repository
- **Documentation**: Check the source code for custom rule definitions

## 🔧 Advanced: Custom Rules

You can extend Kavach with custom security rules:

```python
from kavach import KavachMiddleware, Rule
import re

custom_rules = [
    Rule(
        id="custom-dangerous-function",
        name="Dangerous Function Detector",
        severity="high",
        patterns=[re.compile(r"(eval|exec|compile)")]
    )
]

middleware = KavachMiddleware(rules=custom_rules)
```

## 📝 Next Steps

- Integrate Kavach into your MCP server
- Define custom rules for your specific security requirements
- Monitor violations for suspicious patterns
- Adjust strict/lenient mode based on your use case

---

**Built with Kavach MCP Security Middleware**
