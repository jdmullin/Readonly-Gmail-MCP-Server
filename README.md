# Read-Only Gmail MCP Server

A secure, read-only Model Context Protocol (MCP) server for Gmail integration. This is a security-hardened fork that removes all write operations and encrypts credentials.

## Security Features

- **Read-only access**: Only 5 read-only tools (no send, delete, modify, or filter creation)
- **Encrypted credentials**: AES-256-GCM encryption with machine-derived keys
- **Restricted OAuth scope**: Uses `gmail.readonly` only
- **Secure file permissions**: Credentials saved with mode 600
- **No custom callbacks**: OAuth callback hardcoded to localhost (prevents phishing)

## Available Tools

| Tool | Description |
|------|-------------|
| `read_email` | Read email content by message ID |
| `search_emails` | Search emails using Gmail query syntax |
| `list_email_labels` | List all available labels |
| `list_filters` | List all Gmail filters |
| `get_filter` | Get details of a specific filter |

## Installation & Authentication

### 1. Create Google Cloud OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Gmail API for your project
4. Go to "APIs & Services" > "Credentials"
5. Click "Create Credentials" > "OAuth client ID"
6. Choose "Desktop app" as application type
7. Download the JSON file and rename it to `gcp-oauth.keys.json`

### 2. Run Authentication

```bash
# Place OAuth keys in the config directory
mkdir -p ~/.gmail-mcp
mv gcp-oauth.keys.json ~/.gmail-mcp/

# Navigate to the project and authenticate
cd /path/to/Readonly-Gmail-MCP-Server
npm run auth
```

This will:
- Open your browser for Google authentication
- Request only `gmail.readonly` scope
- Save encrypted credentials to `~/.gmail-mcp/credentials.json`

### 3. Configure in Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "gmail": {
      "command": "node",
      "args": [
        "/path/to/Readonly-Gmail-MCP-Server/dist/index.js"
      ]
    }
  }
}
```

## Usage Examples

Once configured, you can ask Claude things like:

- "Search my Gmail for emails from john@example.com"
- "Find unread emails from the last week"
- "Read the email with subject 'Meeting Notes'"
- "Show me emails with attachments from this month"
- "What labels do I have in Gmail?"
- "List my Gmail filters"

## Search Syntax

The `search_emails` tool supports Gmail's search operators:

| Operator | Example | Description |
|----------|---------|-------------|
| `from:` | `from:john@example.com` | Emails from a sender |
| `to:` | `to:mary@example.com` | Emails to a recipient |
| `subject:` | `subject:"meeting notes"` | Subject contains text |
| `has:attachment` | `has:attachment` | Has attachments |
| `after:` | `after:2024/01/01` | After a date |
| `before:` | `before:2024/02/01` | Before a date |
| `is:` | `is:unread` | Unread emails |
| `label:` | `label:work` | Has a label |

Combine operators: `from:john@example.com after:2024/01/01 has:attachment`

## Security Notes

- Credentials are encrypted with AES-256-GCM using a machine-derived key
- The encryption key is derived from: hostname + username + home directory
- Credentials are tied to this machine and cannot be copied elsewhere
- OAuth scope is read-only - the server cannot modify your Gmail even if compromised
- Credential files (`~/.gmail-mcp/credentials.json` and `gcp-oauth.keys.json`) are saved with mode 600 (owner read/write only)

## Migrating from the Original Server

If you previously used `@gongrzhe/server-gmail-autoauth-mcp`:

```bash
# Delete old credentials (they have write permissions)
rm ~/.gmail-mcp/credentials.json

# Re-authenticate with read-only scope
cd /path/to/Readonly-Gmail-MCP-Server
npm run auth
```

## Building from Source

```bash
npm install
npm run build
```

## What Was Removed

This fork removes the following write operations for security:

- `send_email`, `draft_email`
- `modify_email`, `delete_email`
- `batch_modify_emails`, `batch_delete_emails`
- `create_label`, `update_label`, `delete_label`, `get_or_create_label`
- `create_filter`, `delete_filter`, `create_filter_from_template`
- `download_attachment` (filesystem write)

## License

ISC
