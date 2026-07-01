# MCP (Model Context Protocol) for Cisco APIC

This project provides a simple MCP (Model Context Protocol) server that interacts with a Cisco APIC controller.
If you'd like to understand how this works in detail, please check out [this blog post](https://medium.com/@cpaggen/putting-ai-to-work-with-your-cisco-application-centric-infrastructure-fabric-a-mcp-server-for-aci-838e6fe62022)

- Tested with **Claude Desktop** and **Visual Studio Code** in Agent mode with Copilot.
- The server runs in **STDIO mode**, intended for local execution.

## Features

- Exposes two tools for APIC interaction (see `app/main.py` for details).
- Pluggable authentication: certificate (X.509 signature auth), OS credential
  manager (keyring), or a `.env` file.

## Credentials

Run the one-time setup wizard in a terminal **before** registering the server.
A STDIO MCP server speaks the protocol over stdin/stdout, so it can't prompt for
credentials at launch — this command is that prompt.

```bash
uv run python app/setup.py                      # interactive: choose cert / keyring / .env
```

It can also be scripted (no prompts), which is handy for containers or automated
installs:

```bash
uv run python app/setup.py --auth-method cert    --base-url https://apic.example.com --username svc-aci
uv run python app/setup.py --auth-method keyring --base-url https://apic.example.com --username svc-aci
APIC_PASSWORD=... uv run python app/setup.py --auth-method dotenv --base-url ... --username svc-aci
```

The chosen method is recorded (non-secret) as `APIC_AUTH_METHOD` in `.env`, and
the runtime honors it. You can also pin it directly in the client registration
via the `env` block (see `.vscode/mcp.json`), e.g. `"APIC_AUTH_METHOD": "cert"`.

| Method | How the secret is stored | Notes |
|--------|--------------------------|-------|
| `cert` (recommended) | Private key in a file (chmod 600); **no password** | Wizard generates a keypair and prints the certificate to register in APIC under *Admin > AAA > Users > \<user\> > User Certificates*. Each request is signed; nothing reusable to leak. |
| `keyring` | OS credential manager (Keychain / Windows Credential Mgr / libsecret) | Password never touches disk or the environment. |
| `dotenv` | Plaintext in `.env` | Least secure; explicit opt-in fallback. |

Other settings (all optional, in `.env` or the client `env` block):
`APIC_BASE_URL`, `APIC_USERNAME`, `APIC_VERIFY_SSL` (default `false`; set `true`
and configure trusted certs in production).

## Setup

1. **Configure credentials** by running `uv run python app/setup.py` (see above).
2. If you want Claude or VS Code to run the Python code directly (no container), install [UV](https://docs.astral.sh/uv/)
3. **Register the MCP server** with Claude or VS Code.

   For VS Code, create a `.vscode/mcp.json` file like this in your workspace:

   ```json
   {
     "servers": {
       "ciscoApicServer": {
         "type": "stdio",
         "command": "C:\\Users\\cpaggen\\.local\\bin\\uv.EXE",
         "args": [
           "run",
           "--with",
           "mcp[cli]",
           "mcp",
           "run",
           "C:\\MCP\\app\\main.py"
         ]
       }
     }
   }
   ```

3. Instruct Claude Desktop or VS Code to use it:
   - See [Claude Desktop Quickstart](https://modelcontextprotocol.io/quickstart/user)
   - See [VS Code Copilot MCP Servers](https://code.visualstudio.com/docs/copilot/chat/mcp-servers)

4. **Install MCP client tools locally** if you invoke the MCP server with `uv run mcp` as above.
   - Use ```uv add "mcp[cli]"``` or ```pip install "mcp[cli]"```

## Docker Support

You can run the server directly using UV, or build a Docker image and run it as a container. If using Docker, adapt the `mcp.json` config accordingly.

> **Note:** Local installation of MCP client tools is recommended for debugging the server code.

## Screenshots

Below are some screenshots demonstrating the MCP server in action and its integration with Claude Desktop and VS Code:

| MCP Server Registered | Tool Registered in Claude | Claude Tools List |
|----------------------|--------------------------|------------------|
| ![MCP Server Registered](screenshots/01a-mcp_server_registered.png) | ![Tool Registered in Claude](screenshots/01b-tool_registered_in_claude.png) | ![Claude Tools List](screenshots/01c-claude_tools_list.png) |

| MCP Server Output | Sample Question in VS Code | Sample Question in Claude |
|-------------------|---------------------------|--------------------------|
| ![MCP Server Output](screenshots/02-mcp_server_output.png) | ![Sample Question VS Code](screenshots/03a-sample_question_vscode.png) | ![Sample Claude Question](screenshots/03b-sample_claude_question.png) |

| How to Use ACI Backup |
|----------------------|
| ![How to Use ACI Backup](screenshots/04-how_to_use_aci_backup.png) |

These images illustrate the registration process, available tools, and example interactions.
