#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
# KAVACH MCP - AUTOMATED SETUP SCRIPT
# ══════════════════════════════════════════════════════════════════════════════
# 
# PURPOSE: Automate environment setup in one command
# WHAT IT DOES:
#   1. Check if Python 3 is installed
#   2. Create isolated virtual environment (venv/)
#   3. Activate the environment
#   4. Upgrade pip to latest version
#   5. Install dependencies from requirements.txt
#
# USAGE: bash setup.sh
# RESULT: Ready to run demos and examples
#
# ══════════════════════════════════════════════════════════════════════════════

echo "=========================================="
echo "Kavach MCP Setup"
echo "=========================================="
echo ""

# STEP 1: Verify Python 3 is installed
# Requirement: Python 3.8+ (we need f-strings, type hints, etc.)
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"
echo ""

# STEP 2: Create virtual environment
# Why venv? Isolates project dependencies from system Python
# Prevents conflicts with other projects
echo "📦 Creating virtual environment..."
python3 -m venv venv

# STEP 3: Activate virtual environment
# After this, 'python' and 'pip' commands use venv's Python, not system
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# STEP 4: Upgrade pip
# pip is Python's package installer
# Keep it updated for security and latest features
echo "📈 Upgrading pip..."
pip install --upgrade pip

# STEP 5: Install project dependencies
# requirements.txt lists all packages needed:
# • kavach-mcp - Security middleware
# • fastmcp - MCP server framework
# • uvicorn - ASGI server
# • pydantic - Data validation
echo "📚 Installing dependencies..."
pip install -r requirements.txt

echo ""
echo "=========================================="
echo "✅ Setup Complete!"
echo "=========================================="
echo ""
echo "To activate the environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "To run the demo, execute:"
echo "  python main.py"
echo ""
