"""Safe MCP server for testing — should produce zero findings."""

import os
import subprocess
from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe-server")

WORKSPACE_DIR = Path("/data/workspace")
ALLOWED_COMMANDS = {"git", "ls", "cat"}
SAFE_ENV_VARS = ["APP_ENV", "APP_VERSION", "PORT"]


@mcp.tool()
def run_command(command: str, args: list[str]) -> str:
    """Run an allowed command in the workspace.

    Args:
        command: One of: git, ls, cat
        args: Command arguments (max 10)
    """
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not allowed: {command}")
    if len(args) > 10:
        raise ValueError("Too many arguments")
    result = subprocess.run(
        [command, *args],
        capture_output=True,
        text=True,
        cwd=WORKSPACE_DIR,
    )
    return result.stdout


@mcp.tool()
def read_file(file_path: str) -> str:
    """Read a file from the workspace directory.

    Args:
        file_path: Relative path within the workspace
    """
    resolved = (WORKSPACE_DIR / file_path).resolve()
    if not str(resolved).startswith(str(WORKSPACE_DIR)):
        raise ValueError("Access denied: path outside workspace")
    return resolved.read_text()


@mcp.tool()
def get_config() -> str:
    """Get application configuration values."""
    config = {key: os.environ.get(key, "not set") for key in SAFE_ENV_VARS}
    return str(config)


@mcp.tool()
def get_status(service: str) -> str:
    """Get the status of a service.

    Args:
        service: One of: api, database, cache
    """
    allowed = {"api", "database", "cache"}
    if service not in allowed:
        raise ValueError(f"Unknown service: {service}")
    statuses = {"api": "healthy", "database": "healthy", "cache": "degraded"}
    return f'{{"service": "{service}", "status": "{statuses[service]}"}}'


@mcp.tool()
def process_data(input_text: str) -> str:
    """Process some data.

    Args:
        input_text: Text to process (max 1000 chars)
    """
    if len(input_text) > 1000:
        raise ValueError("Input too long")
    try:
        return input_text.upper()
    except Exception:
        return "An error occurred while processing data."


if __name__ == "__main__":
    mcp.run()
