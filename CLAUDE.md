# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Read-only Gmail MCP Server - A secure, read-only TypeScript MCP (Model Context Protocol) server for Gmail integration. This is a security-hardened fork that removes all write operations and encrypts credentials.

## Build Commands

```bash
npm run build    # Compile TypeScript to dist/
npm start        # Run the server
npm run auth     # Run OAuth authentication flow
```

## Architecture

### Core Files

- **src/index.ts** - Main MCP server. Handles OAuth2 auth with encrypted credential storage, MCP tool registration, and Gmail API read operations. Uses AES-256-GCM encryption for credentials with machine-derived keys.

- **src/label-manager.ts** - Read-only label operations. Exports `listLabels()`, `findLabelByName()`, `GmailLabel` interface.

- **src/filter-manager.ts** - Read-only filter operations. Exports `listFilters()`, `getFilter()`.

### MCP Tools (5 read-only)

1. `read_email` - Read email content by ID
2. `search_emails` - Search emails using Gmail query syntax
3. `list_email_labels` - List all available labels
4. `list_filters` - List all Gmail filters
5. `get_filter` - Get details of a specific filter

### Security Features

- **Read-only OAuth scope**: Uses `gmail.readonly` only (no write permissions)
- **Encrypted credentials**: AES-256-GCM encryption with machine-derived key
- **Restricted file permissions**: Credentials saved with mode 600
- **No custom OAuth callback**: Hardcoded to localhost only (prevents phishing)

### Credential Storage

- OAuth keys: `~/.gmail-mcp/gcp-oauth.keys.json` (mode 600)
- Credentials: `~/.gmail-mcp/credentials.json` (encrypted, mode 600)
- Encryption key derived from: hostname + username + homedir

## Key Dependencies

- `@modelcontextprotocol/sdk` - MCP protocol
- `googleapis` / `google-auth-library` - Gmail API access
- `zod` - Schema validation for tool inputs
- Node.js `crypto` - Built-in encryption (no external deps)
