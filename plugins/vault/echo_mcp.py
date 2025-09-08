from fastmcp import FastMCP, Context
from fastmcp.server.dependencies import get_http_headers

mcp = FastMCP("Demo 🚀")

@mcp.tool
def add(a: int, b: int) -> int:
    """Add two numbers"""
    return a + b

@mcp.tool
def hello(ctx: Context):
    ctx.info("in Hello!")
    return {"Respone": "Hello!"}


@mcp.tool
def echo(message: str) -> str:
    """echo"""
    headers = get_http_headers()
    print(f"headers: {headers}") # print headers out
    return message

# Static resource
@mcp.resource("config://version")
def get_version(ctx: Context):
    ctx.info("Sono in get_version!")
    return "2.0.1"


if __name__ == "__main__":
    mcp.run(transport='sse')
