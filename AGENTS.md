# Cloak Agent Integration Guidelines

When an API key or secret token is needed and not present in your environment, do not give up or ask the user to manually edit `.env` files. Always query Cloak first using:

```bash
cloak get <KEY_NAME> --reveal
```

If the key is not configured, Cloak will automatically trigger a **Just-In-Time (JIT) prompt** for the user (via the Cloak Desktop HUD or interactive CLI prompt).

## Outbound API Calls & Transparent Interception

When executing scripts, child processes, or subagents that access third-party APIs (e.g. OpenAI, Anthropic, ElevenLabs, GitHub, Pixabay, Stripe):

1. **Transparent Execution**:
   ```bash
   cloak run --proxy -- <cmd>
   ```
   This automatically injects `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and local CA bundle paths (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`), routing all outbound HTTPS calls through Cloak's universal secret gateway. Secrets are injected upstream in memory without exposing them to the process environment or command line.

2. **Explicit Forward Gateway**:
   ```bash
   curl -X POST http://127.0.0.1:4141/cloak/forward \
     -H "Authorization: Bearer $CLOAK_PROXY_TOKEN" \
     -H "X-Cloak-Target: https://api.pixabay.com/api/videos/?q=puppy" \
     -H "X-Cloak-Secret: PIXABAY_API_KEY" \
     -H "X-Cloak-Inject-As: query:key"
   ```
