# CAT P2P — Step 4 Public Internet Server

This folder is a GitHub/Render deployment package for CAT's temporary presence + signaling service.

Do not copy this whole folder into the Flutter app. It is a separate server deployment project.

Server files:
- server/cat_directory_server.dart
- server/pubspec.yaml
- Dockerfile
- render.yaml

The server has no persistent CAT database and no application-level message/file storage. It keeps live presence/challenge/signaling state in memory only.

For the first test, the Render Blueprint is configured for the free web-service plan. Do not use the free plan as the final production setup; it can spin down after 15 minutes of inactivity. Upgrade to a paid always-on service before a real public launch.

Once the public URL exists, the Android app can be run with:

flutter run -d <device-id> --dart-define=CAT_DIRECTORY_URL=https://YOUR-SERVICE.onrender.com

The next step after public server deployment is actual WebRTC/P2P data-channel establishment and then the production cryptographic session/message protocol.
