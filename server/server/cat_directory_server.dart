import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

const int serverPort = int.fromEnvironment('PORT', defaultValue: 10000);
const int sessionTtlSeconds = 45;

final _random = Random.secure();
final _ed25519 = Ed25519();

final Map<WebSocket, PendingHandshake> _pending = {};
final Map<String, CatSession> _sessions = {};

class PendingHandshake {
  final String nonce;
  final DateTime createdAt;

  PendingHandshake(this.nonce) : createdAt = DateTime.now();
}

class CatSession {
  final String catId;
  final String publicKey;
  final WebSocket socket;
  DateTime lastSeen;

  CatSession({
    required this.catId,
    required this.publicKey,
    required this.socket,
  }) : lastSeen = DateTime.now();
}

String _encode(List<int> bytes) =>
    base64UrlEncode(bytes).replaceAll('=', '');

List<int> _decode(String value) =>
    base64Url.decode(base64Url.normalize(value));

String _catIdFromPublicKey(List<int> publicKeyBytes) {
  final digestBytes = crypto.sha256.convert(publicKeyBytes).bytes;

  final firstEight = digestBytes
      .take(8)
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();

  final number =
      BigInt.parse(firstEight, radix: 16) % BigInt.from(100000000);

  return number.toInt().toString().padLeft(8, '0');
}

void _send(WebSocket socket, Map<String, dynamic> message) {
  try {
    socket.add(jsonEncode(message));
  } catch (_) {
    // Socket is already closed.
  }
}

void _error(WebSocket socket, String code, String message) {
  _send(socket, {
    'type': 'error',
    'code': code,
    'message': message,
  });
}

Future<void> _handleSocket(WebSocket socket) async {
  final challenge = _encode(List<int>.generate(32, (_) => _random.nextInt(256)));
  _pending[socket] = PendingHandshake(challenge);

  _send(socket, {
    'type': 'challenge',
    'nonce': challenge,
  });

  late StreamSubscription subscription;

  subscription = socket.listen(
    (raw) async {
      try {
        if (raw is! String) {
          _error(socket, 'INVALID_FRAME', 'Only JSON text messages are supported.');
          return;
        }

        if (raw.length > 1024 * 1024) {
          _error(socket, 'MESSAGE_TOO_BIG', 'Message is too large.');
          await socket.close(WebSocketStatus.messageTooBig);
          return;
        }

        final decoded = jsonDecode(raw);
        if (decoded is! Map) {
          _error(socket, 'INVALID_JSON', 'Expected a JSON object.');
          return;
        }

        final message = Map<String, dynamic>.from(decoded);
        final session = _sessionForSocket(socket);

        if (session == null) {
          final type = message['type'];

          if (type != 'register') {
            _error(socket, 'NOT_REGISTERED', 'Register this CAT device first.');
            return;
          }

          final pending = _pending[socket];
          if (pending == null) {
            _error(socket, 'HANDSHAKE_EXPIRED', 'Handshake expired.');
            await socket.close(WebSocketStatus.policyViolation);
            return;
          }

          if (DateTime.now().difference(pending.createdAt).inSeconds > 15) {
            _error(socket, 'HANDSHAKE_EXPIRED', 'Handshake expired.');
            await socket.close(WebSocketStatus.policyViolation);
            return;
          }

          final catId = (message['catId'] as String?)?.trim();
          final publicKeyText = (message['publicKey'] as String?)?.trim();
          final signatureText = (message['signature'] as String?)?.trim();

          if (catId == null ||
              publicKeyText == null ||
              signatureText == null ||
              !RegExp(r'^CAT-\d{4}-\d{4}$').hasMatch(catId)) {
            _error(socket, 'INVALID_REGISTER', 'Invalid registration payload.');
            return;
          }

          final publicKeyBytes = _decode(publicKeyText);
          final signatureBytes = _decode(signatureText);

          if (publicKeyBytes.length != 32 || signatureBytes.length != 64) {
            _error(socket, 'INVALID_KEY', 'Invalid Ed25519 key or signature length.');
            return;
          }

          final expectedDigits = _catIdFromPublicKey(publicKeyBytes);
          final expectedCatId = 'CAT-$expectedDigits';

          if (catId != expectedCatId) {
            _error(
              socket,
              'CAT_ID_BINDING_FAILED',
              'CAT ID does not match the device public key.',
            );
            return;
          }

          final publicKey = SimplePublicKey(
            publicKeyBytes,
            type: KeyPairType.ed25519,
          );

          final signature = Signature(
            signatureBytes,
            publicKey: publicKey,
          );

          final signedText = '$catId|$publicKeyText|${pending.nonce}';

          final verified = await _ed25519.verifyString(
            signedText,
            signature: signature,
          );

          if (!verified) {
            _error(
              socket,
              'AUTH_FAILED',
              'The device could not prove ownership of this CAT identity.',
            );
            await socket.close(WebSocketStatus.policyViolation);
            return;
          }

          final old = _sessions[catId];
          if (old != null && old.socket != socket) {
            try {
              await old.socket.close(WebSocketStatus.policyViolation);
            } catch (_) {}
          }

          _sessions[catId] = CatSession(
            catId: catId,
            publicKey: publicKeyText,
            socket: socket,
          );
          _pending.remove(socket);

          _send(socket, {
            'type': 'registered',
            'catId': catId,
            'online': true,
          });

          return;
        }

        switch (message['type']) {
          case 'heartbeat':
            session.lastSeen = DateTime.now();
            _send(socket, {
              'type': 'heartbeat_ack',
            });
            break;

          case 'lookup':
            final target = (message['catId'] as String?)?.trim();

            if (target == null ||
                !RegExp(r'^CAT-\d{4}-\d{4}$').hasMatch(target)) {
              _error(socket, 'INVALID_CAT_ID', 'Invalid CAT ID.');
              return;
            }

            final targetSession = _liveSession(target);

            _send(socket, {
              'type': 'lookup_result',
              'catId': target,
              'online': targetSession != null,
            });
            break;

          case 'signal':
            final target = (message['to'] as String?)?.trim();
            final kind = (message['kind'] as String?)?.trim();
            final data = message['data'];

            if (target == null ||
                kind == null ||
                data == null ||
                !RegExp(r'^CAT-\d{4}-\d{4}$').hasMatch(target)) {
              _error(socket, 'INVALID_SIGNAL', 'Invalid signaling message.');
              return;
            }

            final targetSession = _liveSession(target);

            if (targetSession == null) {
              _send(socket, {
                'type': 'signal_result',
                'to': target,
                'delivered': false,
                'reason': 'OFFLINE',
              });
              return;
            }

            _send(targetSession.socket, {
              'type': 'signal',
              'from': session.catId,
              'kind': kind,
              'data': data,
            });

            _send(socket, {
              'type': 'signal_result',
              'to': target,
              'delivered': true,
            });
            break;

          default:
            _error(socket, 'UNKNOWN_TYPE', 'Unknown message type.');
        }
      } catch (error) {
        _error(socket, 'SERVER_ERROR', 'The server could not process that message.');
        stderr.writeln('Socket message error: $error');
      }
    },
    onError: (_) async {
      await _removeSocket(socket);
    },
    onDone: () async {
      await _removeSocket(socket);
      await subscription.cancel();
    },
    cancelOnError: false,
  );
}

CatSession? _sessionForSocket(WebSocket socket) {
  for (final session in _sessions.values) {
    if (session.socket == socket) {
      return session;
    }
  }
  return null;
}

CatSession? _liveSession(String catId) {
  final session = _sessions[catId];
  if (session == null) return null;

  final age = DateTime.now().difference(session.lastSeen).inSeconds;
  if (age > sessionTtlSeconds) {
    _sessions.remove(catId);
    try {
      session.socket.close(WebSocketStatus.goingAway);
    } catch (_) {}
    return null;
  }

  return session;
}

Future<void> _removeSocket(WebSocket socket) async {
  _pending.remove(socket);

  String? catIdToRemove;

  for (final entry in _sessions.entries) {
    if (entry.value.socket == socket) {
      catIdToRemove = entry.key;
      break;
    }
  }

  if (catIdToRemove != null) {
    final session = _sessions[catIdToRemove];
    if (session?.socket == socket) {
      _sessions.remove(catIdToRemove);
    }
  }
}

Future<void> _cleanupExpiredSessions() async {
  final now = DateTime.now();

  final expiredIds = <String>[];
  for (final entry in _sessions.entries) {
    if (now.difference(entry.value.lastSeen).inSeconds > sessionTtlSeconds) {
      expiredIds.add(entry.key);
    }
  }

  for (final catId in expiredIds) {
    final session = _sessions.remove(catId);
    if (session != null) {
      try {
        await session.socket.close(WebSocketStatus.goingAway);
      } catch (_) {}
    }
  }

  final expiredPending = <WebSocket>[];
  for (final entry in _pending.entries) {
    if (now.difference(entry.value.createdAt).inSeconds > 15) {
      expiredPending.add(entry.key);
    }
  }

  for (final socket in expiredPending) {
    _pending.remove(socket);
    try {
      await socket.close(WebSocketStatus.policyViolation);
    } catch (_) {}
  }
}

Future<void> main() async {
  final server = await HttpServer.bind(InternetAddress.anyIPv4, serverPort);

  print('CAT public server listening on http://0.0.0.0:$serverPort');
  print('Mode: ephemeral presence + signaling (no persistent CAT data)');

  Timer.periodic(
    const Duration(seconds: 15),
    (_) => _cleanupExpiredSessions(),
  );

  await for (final request in server) {
    if (request.uri.path == '/health') {
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode({
        'ok': true,
        'service': 'cat-step2',
        'mode': 'ephemeral-presence-and-signaling',
      }));
      await request.response.close();
      continue;
    }

    if (request.uri.path == '/ws' &&
        WebSocketTransformer.isUpgradeRequest(request)) {
      try {
        final socket = await WebSocketTransformer.upgrade(request);
        unawaited(_handleSocket(socket));
      } catch (error) {
        stderr.writeln('WebSocket upgrade failed: $error');
        try {
          await request.response.close();
        } catch (_) {}
      }
      continue;
    }

    request.response.statusCode = HttpStatus.notFound;
    await request.response.close();
  }
}