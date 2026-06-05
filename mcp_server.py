from fastapi import FastAPI
from fastmcp import FastMCP
from kavach import KavachMiddleware # apni file ka naam yahan likhein
import uvicorn

mcp = FastMCP("Secure MCP")

# 1. Instance create karein
kavach = KavachMiddleware(
    strict=True,
    sensitive_tools=["generate_report", "add"] # Yahan un tools ke naam daalein jo aap test kar rahe hain
)

# 2. Middleware add karein
mcp.add_middleware(kavach)

@mcp.tool
def generate_report(query: str):
    return {"report": f"Generated for {query}"}

# SSE connection testing ke liye ek dummy 'add' tool jaisa ki aapke screenshot mein tha
@mcp.tool
def add(a: int, b: int):
    return {"result": a + b}

mcp_app = mcp.http_app(path="/")

app = FastAPI(lifespan=mcp_app.lifespan)
app.mount("/mcp", mcp_app)

if __name__ == "__main__":
    uvicorn.run("mcp_server:app", host="0.0.0.0", port=8000, reload=True)