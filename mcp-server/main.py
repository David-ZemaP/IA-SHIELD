from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from tools.safebrowsing import verify_url_safebrowsing

app = FastAPI(title="IA-Seguridad MCP Server")

# JSON-RPC request model
class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    method: str
    params: dict | None = None
    id: str | int | None = None

@app.post("/tools/verify-url")
async def verify_url(request: dict):
    """
    MCP tool endpoint for URL verification.
    Request body: {"url": "https://example.com"}
    Returns: {"success": true, "result": {...}} or {"success": false, "error": "..."}
    """
    url = request.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="Missing 'url' parameter")

    try:
        result = verify_url_safebrowsing(url)
        return {"success": True, "result": result}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/health")
async def health():
    return {"status": "ok", "service": "mcp-server"}

if __name__ == "__main__":
    import uvicorn
    from config import get_config
    cfg = get_config()
    uvicorn.run(app, host=cfg["HOST"], port=cfg["PORT"])