# supplyscan-mcp

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io)

A Go-based MCP (Model Context Protocol) server that scans JavaScript ecosystem lockfiles for supply chain compromises and known vulnerabilities.

Being implemented in Go rather than as an npm package makes it immune to npm supply chain attacks by design.

## Features

- **Supply chain detection**: Identifies compromised packages by aggregating multiple IOC sources (DataDog, GitHub Advisory Database)
- **Vulnerability scanning**: Integrates with npm audit API to find known CVEs
- **Multi-format support**: Parses lockfiles from npm, Yarn (classic & berry), pnpm, Bun, and Deno
- **Dual mode**: Runs as an MCP server or standalone CLI tool
- **Per-source caching**: Each IOC source cached independently with configurable TTL

## Supported Lockfiles

| Package Manager | Lockfile |
|-----------------|----------|
| npm | `package-lock.json`, `npm-shrinkwrap.json` |
| Yarn Classic | `yarn.lock` (v1) |
| Yarn Berry | `yarn.lock` (v2+) |
| pnpm | `pnpm-lock.yaml` |
| Bun | `bun.lock` |
| Deno | `deno.lock` |

## Installation

### Claude Code CLI (Recommended)

Install with a single command - no config editing required:

**Ephemeral cache (maximum privacy):**
```bash
claude mcp add supplyscan -s user -- \
  sh -c 'docker run --rm -i --pull always -v "$PWD:/workspace:ro" --tmpfs /cache ghcr.io/seanhalberthal/supplyscan-mcp:latest'
```

**Persistent cache (faster startup):**
```bash
claude mcp add supplyscan -s user -- \
  sh -c 'docker run --rm -i --pull always -v "$PWD:/workspace:ro" -v supplyscan-cache:/cache ghcr.io/seanhalberthal/supplyscan-mcp:latest'
```

This adds supplyscan to your user-level config, available across all projects. Restart Claude Code to activate.

**What this does:**
- Mounts only your current working directory (read-only)
- Ephemeral: uses in-memory cache (tmpfs) - nothing persists on your filesystem
- Persistent: uses a Docker-managed volume - doesn't touch your home directory
- Runs as non-root user inside the container

### Docker (Manual Config)

Alternatively, configure manually. Docker pulls the image automatically on first run.

Skip to [Configuration](#configuration).

### Build from Source

If you prefer a native binary (requires Go 1.23+):

```bash
git clone https://github.com/seanhalberthal/supplyscan-mcp.git
cd supplyscan-mcp
go build -o supplyscan-mcp ./cmd
# Optionally move to PATH
mv supplyscan-mcp /usr/local/bin/
```

### Download Binary

```bash
# macOS (Apple Silicon)
curl -L https://github.com/seanhalberthal/supplyscan-mcp/releases/latest/download/supplyscan-mcp-darwin-arm64 \
  -o /usr/local/bin/supplyscan-mcp && chmod +x /usr/local/bin/supplyscan-mcp

# macOS (Intel)
curl -L https://github.com/seanhalberthal/supplyscan-mcp/releases/latest/download/supplyscan-mcp-darwin-amd64 \
  -o /usr/local/bin/supplyscan-mcp && chmod +x /usr/local/bin/supplyscan-mcp

# Linux (x64)
curl -L https://github.com/seanhalberthal/supplyscan-mcp/releases/latest/download/supplyscan-mcp-linux-amd64 \
  -o /usr/local/bin/supplyscan-mcp && chmod +x /usr/local/bin/supplyscan-mcp

# Windows
# Download from GitHub releases and add to PATH
```

## Configuration

These manual configurations are alternatives to the [CLI install](#claude-code-cli-recommended) method above.

### Privacy Model

The Docker configurations below follow a privacy-first approach:
- **Read-only project access**: Only the current project directory is mounted, and as read-only
- **Ephemeral cache**: Uses tmpfs (in-memory) so nothing persists on your filesystem
- **Non-root execution**: Container runs as UID 1000, not root

### Claude Code / Claude Desktop (Docker)

Add to your MCP config file (`~/.claude.json` for Claude Code, `claude_desktop_config.json` for Claude Desktop):

**Ephemeral cache (maximum privacy):**
```json
{
  "mcpServers": {
    "supplyscan": {
      "command": "sh",
      "args": [
        "-c",
        "docker run --rm -i --pull always -v \"$PWD:/workspace:ro\" --tmpfs /cache ghcr.io/seanhalberthal/supplyscan-mcp:latest"
      ]
    }
  }
}
```

**Persistent cache (faster startup):**
```json
{
  "mcpServers": {
    "supplyscan": {
      "command": "sh",
      "args": [
        "-c",
        "docker run --rm -i --pull always -v \"$PWD:/workspace:ro\" -v supplyscan-cache:/cache ghcr.io/seanhalberthal/supplyscan-mcp:latest"
      ]
    }
  }
}
```

The shell wrapper allows `$PWD` to be evaluated at runtime, mounting your current working directory.

### Cursor / VS Code (Docker)

These IDEs support workspace variables, which makes configuration cleaner:

**Ephemeral cache (maximum privacy):**
```json
{
  "mcpServers": {
    "supplyscan": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--pull", "always",
        "-v", "${workspaceFolder}:/workspace:ro",
        "--tmpfs", "/cache",
        "ghcr.io/seanhalberthal/supplyscan-mcp:latest"
      ]
    }
  }
}
```

**Persistent cache (faster startup):**
```json
{
  "mcpServers": {
    "supplyscan": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--pull", "always",
        "-v", "${workspaceFolder}:/workspace:ro",
        "-v", "supplyscan-cache:/cache",
        "ghcr.io/seanhalberthal/supplyscan-mcp:latest"
      ]
    }
  }
}
```

### Binary

If using a native binary (built from source or downloaded):

```json
{
  "mcpServers": {
    "supplyscan": {
      "command": "supplyscan-mcp"
    }
  }
}
```

The binary stores its cache in `~/.cache/supplyscan-mcp/` by default. Override with `SUPPLYSCAN_CACHE_DIR` environment variable.

## MCP Tools

### `supplyscan_status`

Get scanner version, IOC database info, and supported lockfile formats.

### `supplyscan_scan`

Scan a project directory for supply chain compromises and known vulnerabilities.

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | string | Path to the project directory |
| `recursive` | boolean | Scan subdirectories for lockfiles |
| `include_dev` | boolean | Include dev dependencies |

### `supplyscan_check`

Check a single package@version for supply chain compromises and vulnerabilities.

| Parameter | Type | Description |
|-----------|------|-------------|
| `package` | string | Package name |
| `version` | string | Package version |

### `supplyscan_refresh`

Update the IOC database from upstream sources.

| Parameter | Type | Description |
|-----------|------|-------------|
| `force` | boolean | Force refresh even if cache is fresh |

## CLI Mode

The MCP server runs via stdio by default, but includes a CLI mode for standalone testing.

### Docker

```bash
# Scan current directory
docker run --rm --pull always -v "$PWD:/workspace:ro" --tmpfs /cache \
  ghcr.io/seanhalberthal/supplyscan-mcp:latest --cli scan /workspace

# Scan a specific directory
docker run --rm --pull always -v /path/to/project:/workspace:ro --tmpfs /cache \
  ghcr.io/seanhalberthal/supplyscan-mcp:latest --cli scan /workspace

# Check a specific package
docker run --rm --pull always --tmpfs /cache \
  ghcr.io/seanhalberthal/supplyscan-mcp:latest --cli check lodash 4.17.20

# Refresh IOC database (ephemeral - for testing)
docker run --rm --pull always --tmpfs /cache \
  ghcr.io/seanhalberthal/supplyscan-mcp:latest --cli refresh

# Show status
docker run --rm --pull always --tmpfs /cache \
  ghcr.io/seanhalberthal/supplyscan-mcp:latest --cli status
```

### Binary

```bash
# Scan current directory
supplyscan-mcp --cli scan .

# Scan specific path recursively
supplyscan-mcp --cli scan /path/to/monorepo --recursive

# Scan production dependencies only (exclude devDependencies)
supplyscan-mcp --cli scan . --no-dev

# Check a specific package
supplyscan-mcp --cli check lodash 4.17.20

# Refresh IOC database
supplyscan-mcp --cli refresh

# Show status
supplyscan-mcp --cli status
```

## Data Sources

### IOC Sources (Aggregated)

- **DataDog IOC Database**: [Indicators of Compromise](https://github.com/DataDog/indicators-of-compromise) - Shai-Hulud campaign packages
- **GitHub Advisory Database**: [Security Advisories](https://github.com/advisories) - npm malware advisories (GHSA)

### Vulnerability Data

- **npm Audit API**: [Registry audit endpoint](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities) - known CVEs

## Building

```bash
# Build for current platform
make build

# Cross-compile for all platforms
make build-all

# Run tests
make test

# Run linter
make lint

# Build Docker image
make docker
```

## License

[MIT](LICENSE)
