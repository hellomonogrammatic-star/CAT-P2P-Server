# CAT Step 4 — Public Internet Server

This is the deployment package for the CAT ephemeral presence + signaling server.

## Privacy model

- No database.
- No CAT user registry is persisted to disk.
- No chat messages or files are stored by the application.
- Live CAT presence, challenge state, and signaling live only in RAM.
- A process restart removes live presence.

## Important test vs production note

The included Render Blueprint uses the free web-service plan for an initial cross-network test. Render states that free web services can spin down after 15 minutes without inbound traffic and can take about a minute to wake. Render also explicitly says free instances are not for production applications.

For a production CAT service, use a paid always-on compute plan and perform security, load, failover, abuse/rate-limit, logging/retention, and independent security testing before launch.

## Deploy on Render

1. Create a GitHub repository containing this folder's files at the repository root.
2. In Render, choose **New → Blueprint** and select that GitHub repository.
3. Render should detect `render.yaml`.
4. Create/apply the Blueprint.
5. Wait for the deploy to complete.
6. Open the service URL, for example:
   `https://cat-directory-xxxx.onrender.com/health`
7. A healthy result should look like:
   `{ "ok": true, ... }`

Render web services receive public traffic on their `onrender.com` URL, provide managed TLS, and support WebSockets. Use `wss://` over the public Internet. See Render's current WebSocket and web-service documentation.

## Connect the CAT Android app

After you know the exact Render URL, do NOT use the local `192.168.x.x` address.

Build/run the CAT app with:

`flutter run -d <device-id> --dart-define=CAT_DIRECTORY_URL=https://YOUR-SERVICE.onrender.com`

The existing Step 3 client converts an HTTPS base URL to WSS for its WebSocket connection.

## Architecture

Phone A -> HTTPS/WSS -> CAT server for temporary presence/signaling
Phone B -> HTTPS/WSS -> CAT server for temporary presence/signaling
Phone A <-> Phone B -> later WebRTC P2P data channel

This Step 4 package does NOT implement the final WebRTC data channel or application-level E2EE messaging. Those are later steps.
