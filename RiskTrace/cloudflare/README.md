# Cloudflare Workers gateway for RiskTrace

This Worker is a fixed-origin HTTPS gateway. The existing Flask application remains the scanner backend, so its collectors, TCP/TLS checks, SQLite data, and queue behavior stay on the backend machine. The Worker does not accept arbitrary target URLs as proxy destinations.

## Required setup

1. Make the Flask backend reachable over HTTPS at a dedicated origin hostname, for example through a Cloudflare Tunnel. Do not route that hostname back through this Worker.
2. Configure the backend with a long random `RISKTRACE_PROXY_TOKEN`, a stable `RISKTRACE_SECRET`, and `RISKTRACE_PASSWORD`.
3. Set `RISKTRACE_ORIGIN` in `wrangler.jsonc` to the backend origin. The origin must be HTTPS and have no path.
4. From this directory, install Wrangler dependencies and store the same proxy token as a Worker secret:

   ```powershell
   npm install
   npx wrangler secret put RISKTRACE_PROXY_TOKEN
   ```

5. Test the gateway locally with `npm run dev`, then publish it with `npm run deploy`.

The backend rejects requests that do not include the Worker secret when `RISKTRACE_PROXY_TOKEN` is configured. `ProxyFix` then uses the forwarded public host and HTTPS scheme so Flask redirects and generated URLs stay on the Worker hostname. The session cookie is marked Secure in this mode.

The Worker itself does not store scan data. Keep the SQLite database and scanner backend running with persistent storage. Deploying the Worker requires an authenticated Cloudflare account; no credentials or backend hostname are included in this repository.
