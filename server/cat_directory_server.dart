import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:cryptography/cryptography.dart';

/// CAT Step 2: Internet presence + WebSocket signaling server.
///
/// Privacy model:
/// - No database.
/// - No application files are written.
/// - No permanent CAT-ID registry.
/// - Online CAT IDs, public keys, challenges, and signaling state live only
///   in memory while a device is connected.
/// - A server restart removes all online presence.
/// - Signaling payloads are forwarded opaquely and are never written to disk.
///
/// Production: put this service behind HTTPS/WSS (for example Caddy).
/// The Flutter client uses the HTTPS base URL for HTTP endpoints and wss://
/// for /v1/presence (registration) and /v1/signal (signaling compatibility).

const _maxHttpBodyBytes = 32 * 1024;
const _maxWebSocketPayloadBytes = 256 * 1024;
const _challengeLifetime = Duration(minutes: 2);
const _presenceInactivityLimit = Duration(minutes: 2);
const _cleanupInterval = Duration(seconds: 30);

final RegExp _catIdPattern = RegExp(r'^CAT-[A-Z0-9]{4}-[A-Z0-9]{4}$');

Future<void> main(List<String> args) async {
  final host = _argValue(args, '--host') ??
      Platform.environment['CAT_HOST'] ??
      '0.0.0.0';
  final port = int.tryParse(
        _argValue(args, '--port') ??
            Platform.environment['PORT'] ??
            Platform.environment['CAT_PORT'] ??
            '10000',
      ) ??
      10000;

  final state = ServerState();
  final server = await HttpServer.bind(host, port);

  stdout.writeln('CAT public server listening on http://$host:$port');
  stdout.writeln('Mode: ephemeral presence + signaling (no persistent CAT data)');

  Timer.periodic(_cleanupInterval, (_) => state.cleanup());

  ProcessSignal.sigint.watch().listen((_) async {
    await server.close(force: true);
    exit(0);
  });

  // SIGTERM signal watching is not supported on Windows.
  // Ctrl+C/SIGINT remains supported for local development.

  await for (final request in server) {
    unawaited(_handleRequest(request, state));
  }
}

Future<void> _handleRequest(HttpRequest request, ServerState state) async {
  final response = request.response;
  _setCommonHeaders(response);

  try {
    if (request.method == 'OPTIONS') {
      response.statusCode = HttpStatus.noContent;
      await response.close();
      return;
    }

    if (request.method == 'GET' && request.uri.path == '/health') {
      await _jsonResponse(request, HttpStatus.ok, {
        'ok': true,
        'service': 'cat-step2',
        'mode': 'ephemeral-presence-and-signaling',
      });
      return;
    }

    if (request.method == 'POST' && request.uri.path == '/v1/presence/challenge') {
      await _createChallenge(request, state);
      return;
    }

    if (request.method == 'GET' && request.uri.path == '/v1/presence' &&
        request.headers.value('upgrade')?.toLowerCase() != 'websocket') {
      await _lookupPresence(request, state);
      return;
    }

    if (request.method == 'GET' &&
        (request.uri.path == '/v1/presence' || request.uri.path == '/v1/signal') &&
        request.headers.value('upgrade')?.toLowerCase() == 'websocket') {
      await _upgradeSignalSocket(request, state);
      return;
    }

    await _jsonResponse(request, HttpStatus.notFound, {'message': 'Not found'});
  } catch (error, stack) {
    stderr.writeln('CAT server internal error: $error');
    stderr.writeln(stack);
    try {
      await _jsonResponse(request, HttpStatus.internalServerError, {
        'message': 'Internal server error',
      });
    } catch (_) {
      // The connection may already be closed or upgraded.
    }
  }
}

Future<void> _createChallenge(HttpRequest request, ServerState state) async {
  if (!state.httpLimiter.allow(_clientKey(request))) {
    await _jsonResponse(request, HttpStatus.tooManyRequests, {
      'message': 'Too many requests',
    });
    return;
  }

  final body = await _readJson(request);
  final catId = body?['catId']?.toString().trim().toUpperCase() ?? '';
  if (!_catIdPattern.hasMatch(catId)) {
    await _jsonResponse(request, HttpStatus.badRequest, {
      'message': 'Invalid CAT ID format',
    });
    return;
  }

  final nonce = _randomUrlSafe(32);
  state.challenges[catId] = Challenge(
    catId: catId,
    nonce: nonce,
    expiresAt: DateTime.now().toUtc().add(_challengeLifetime),
  );

  await _jsonResponse(request, HttpStatus.ok, {
    'nonce': nonce,
    'expiresInSeconds': _challengeLifetime.inSeconds,
  });
}

Future<void> _lookupPresence(HttpRequest request, ServerState state) async {
  if (!state.httpLimiter.allow(_clientKey(request))) {
    await _jsonResponse(request, HttpStatus.tooManyRequests, {
      'message': 'Too many requests',
    });
    return;
  }

  final catId = request.uri.queryParameters['catId']?.trim().toUpperCase() ?? '';
  if (!_catIdPattern.hasMatch(catId)) {
    await _jsonResponse(request, HttpStatus.badRequest, {
      'message': 'Invalid CAT ID format',
    });
    return;
  }

  state.cleanup();
  final presence = state.presenceByCatId[catId];
  if (presence == null || presence.socket.readyState != WebSocket.open) {
    await _jsonResponse(request, HttpStatus.notFound, {
      'online': false,
      'catId': catId,
    });
    return;
  }

  await _jsonResponse(request, HttpStatus.ok, {
    'online': true,
    'catId': presence.catId,
    'signingPublicKey': presence.signingPublicKey,
    'exchangePublicKey': presence.exchangePublicKey,
    'publicFingerprint': presence.publicFingerprint,
    'sessionCreatedAt': presence.createdAt.toUtc().toIso8601String(),
  });
}

Future<void> _upgradeSignalSocket(HttpRequest request, ServerState state) async {
  final upgradeHeader = request.headers.value('upgrade')?.toLowerCase();
  if (upgradeHeader != 'websocket') {
    await _jsonResponse(request, HttpStatus.badRequest, {
      'message': 'WebSocket upgrade required',
    });
    return;
  }

  final socket = await WebSocketTransformer.upgrade(
    request,
    maxPayloadLength: _maxWebSocketPayloadBytes,
  );
  socket.pingInterval = const Duration(seconds: 25);

  SignalConnection? connection;
  StreamSubscription<dynamic>? subscription;
  Timer? inactivityTimer;
  final signalLimiter = RateLimiter(
    maxEvents: 120,
    window: const Duration(seconds: 10),
  );

  void closeConnection([int code = WebSocketStatus.normalClosure]) {
    inactivityTimer?.cancel();
    subscription?.cancel();
    final current = connection;
    if (current != null) {
      state.removePresence(current.catId, current.socket);
    }
    try {
      if (socket.readyState == WebSocket.open ||
          socket.readyState == WebSocket.connecting) {
        socket.close(code, 'closed');
      }
    } catch (_) {}
  }

  subscription = socket.listen(
    (raw) async {
      if (raw is! String || raw.length > _maxWebSocketPayloadBytes) {
        closeConnection(WebSocketStatus.messageTooBig);
        return;
      }

      final data = _decodeObject(raw);
      if (data == null) {
        closeConnection(WebSocketStatus.invalidFramePayloadData);
        return;
      }

      final type = data['type']?.toString();

      if (type == 'hello') {
        if (connection != null) {
          closeConnection(WebSocketStatus.protocolError);
          return;
        }

        final hello = await _authenticateHello(data, state, socket);
        if (hello == null) {
          closeConnection(WebSocketStatus.policyViolation);
          return;
        }

        final previous = state.presenceByCatId[hello.catId];
        if (previous != null && previous.socket != socket) {
          try {
            previous.socket.close(WebSocketStatus.goingAway, 'replaced');
          } catch (_) {}
          state.removePresence(hello.catId, previous.socket);
        }

        connection = hello;
        state.presenceByCatId[hello.catId] = hello;
        state.touch(hello.catId);

        socket.add(jsonEncode({
          'type': 'hello_ack',
          'ok': true,
          'catId': hello.catId,
          'mode': 'ephemeral',
        }));
        return;
      }

      final current = connection;
      if (current == null) {
        closeConnection(WebSocketStatus.policyViolation);
        return;
      }

      state.touch(current.catId);

      if (type == 'presence_ping') {
        socket.add(jsonEncode({'type': 'presence_pong'}));
        return;
      }

      if (type == 'signal') {
        if (!signalLimiter.allow(current.catId)) {
          socket.add(jsonEncode({
            'type': 'signal_error',
            'reason': 'rate-limited',
          }));
          return;
        }
        await _forwardSignal(data, current, state, socket);
        return;
      }

      if (type == 'disconnect') {
        closeConnection();
        return;
      }

      closeConnection(WebSocketStatus.protocolError);
    },
    onDone: () {
      inactivityTimer?.cancel();
      final current = connection;
      if (current != null) {
        state.removePresence(current.catId, current.socket);
      }
      subscription = null;
    },
    onError: (_) {
      closeConnection(WebSocketStatus.internalServerError);
    },
    cancelOnError: true,
  );

  inactivityTimer = Timer.periodic(const Duration(seconds: 30), (_) {
    final current = connection;
    if (current == null) return;
    final touched = state.lastActivity[current.catId];
    if (touched == null ||
        DateTime.now().toUtc().difference(touched) > _presenceInactivityLimit) {
      closeConnection(WebSocketStatus.goingAway);
    }
  });
}

Future<SignalConnection?> _authenticateHello(
  Map<String, dynamic> data,
  ServerState state,
  WebSocket socket,
) async {
  final catId = data['catId']?.toString().trim().toUpperCase() ?? '';
  final signingPublicKeyB64 = data['signingPublicKey']?.toString() ?? '';
  final exchangePublicKeyB64 = data['exchangePublicKey']?.toString() ?? '';
  final fingerprint = data['publicFingerprint']?.toString() ?? '';
  final nonce = data['nonce']?.toString() ?? '';
  final signatureB64 = data['signature']?.toString() ?? '';

  if (!_catIdPattern.hasMatch(catId) ||
      signingPublicKeyB64.isEmpty ||
      exchangePublicKeyB64.isEmpty ||
      nonce.isEmpty ||
      signatureB64.isEmpty) {
    return null;
  }

  final challenge = state.challenges.remove(catId);
  if (challenge == null ||
      challenge.nonce != nonce ||
      DateTime.now().toUtc().isAfter(challenge.expiresAt)) {
    return null;
  }

  final List<int> publicKeyBytes;
  final List<int> signatureBytes;
  try {
    publicKeyBytes = base64Url.decode(signingPublicKeyB64);
    signatureBytes = base64Url.decode(signatureB64);
  } catch (_) {
    return null;
  }

  if (publicKeyBytes.length != 32 || signatureBytes.length != 64) {
    return null;
  }

  final publicKey = SimplePublicKey(
    publicKeyBytes,
    type: KeyPairType.ed25519,
  );
  final message = utf8.encode('CAT-PRESENCE\n$catId\n$nonce');

  bool validProof;
  try {
    validProof = await Ed25519().verify(
      message,
      signature: Signature(signatureBytes, publicKey: publicKey),
    );
  } catch (_) {
    validProof = false;
  }

  if (!validProof) return null;

  return SignalConnection(
    catId: catId,
    signingPublicKey: signingPublicKeyB64,
    exchangePublicKey: exchangePublicKeyB64,
    publicFingerprint: fingerprint,
    socket: socket,
  );
}

Future<void> _forwardSignal(
  Map<String, dynamic> data,
  SignalConnection sender,
  ServerState state,
  WebSocket socket,
) async {
  final recipientCatId = data['toCatId']?.toString().trim().toUpperCase() ?? '';
  if (!_catIdPattern.hasMatch(recipientCatId) || recipientCatId == sender.catId) {
    socket.add(jsonEncode({
      'type': 'signal_error',
      'reason': 'invalid-recipient-cat-id',
    }));
    return;
  }

  final target = state.presenceByCatId[recipientCatId];
  if (target == null || target.socket.readyState != WebSocket.open) {
    socket.add(jsonEncode({
      'type': 'signal_error',
      'reason': 'recipient-offline',
      'toCatId': recipientCatId,
    }));
    return;
  }

  final payload = data['payload'];
  final payloadBytes = utf8.encode(jsonEncode(payload));
  if (payloadBytes.length > _maxWebSocketPayloadBytes) {
    socket.add(jsonEncode({
      'type': 'signal_error',
      'reason': 'signal-too-large',
    }));
    return;
  }

  // Opaque signaling payload: the server forwards it but never interprets
  // SDP/ICE contents or writes them anywhere.
  target.socket.add(jsonEncode({
    'type': 'signal',
    'fromCatId': sender.catId,
    'payload': payload,
  }));
}

void _setCommonHeaders(HttpResponse response) {
  response.headers
    ..set('cache-control', 'no-store')
    ..set('x-content-type-options', 'nosniff')
    ..set('referrer-policy', 'no-referrer');
}

Future<Map<String, dynamic>?> _readJson(HttpRequest request) async {
  final bytes = <int>[];
  await for (final chunk in request) {
    bytes.addAll(chunk);
    if (bytes.length > _maxHttpBodyBytes) return null;
  }
  if (bytes.isEmpty) return null;
  try {
    final decoded = jsonDecode(utf8.decode(bytes));
    return decoded is Map<String, dynamic> ? decoded : null;
  } catch (_) {
    return null;
  }
}

Future<void> _jsonResponse(
  HttpRequest request,
  int status,
  Map<String, dynamic> body,
) async {
  final bytes = utf8.encode(jsonEncode(body));
  final response = request.response
    ..statusCode = status
    ..headers.contentType = ContentType.json
    ..headers.contentLength = bytes.length;
  response.add(bytes);
  await response.close();
}

String _clientKey(HttpRequest request) {
  final forwarded = request.headers.value('x-forwarded-for');
  if (forwarded != null && forwarded.trim().isNotEmpty) {
    return forwarded.split(',').first.trim();
  }
  return request.connectionInfo?.remoteAddress.address ?? 'unknown';
}

String _randomUrlSafe(int byteCount) {
  final bytes = List<int>.generate(
    byteCount,
    (_) => Random.secure().nextInt(256),
  );
  return base64UrlEncode(bytes).replaceAll('=', '');
}

Map<String, dynamic>? _decodeObject(String text) {
  try {
    final decoded = jsonDecode(text);
    return decoded is Map<String, dynamic> ? decoded : null;
  } catch (_) {
    return null;
  }
}

String? _argValue(List<String> args, String name) {
  final index = args.indexOf(name);
  if (index == -1 || index + 1 >= args.length) return null;
  return args[index + 1];
}

class Challenge {
  const Challenge({
    required this.catId,
    required this.nonce,
    required this.expiresAt,
  });

  final String catId;
  final String nonce;
  final DateTime expiresAt;
}

class SignalConnection {
  SignalConnection({
    required this.catId,
    required this.signingPublicKey,
    required this.exchangePublicKey,
    required this.publicFingerprint,
    required this.socket,
  }) : createdAt = DateTime.now().toUtc();

  final String catId;
  final String signingPublicKey;
  final String exchangePublicKey;
  final String publicFingerprint;
  final WebSocket socket;
  final DateTime createdAt;
}

class ServerState {
  final Map<String, Challenge> challenges = {};
  final Map<String, SignalConnection> presenceByCatId = {};
  final Map<String, DateTime> lastActivity = {};
  final RateLimiter httpLimiter = RateLimiter(
    maxEvents: 60,
    window: const Duration(minutes: 1),
  );

  void touch(String catId) {
    lastActivity[catId] = DateTime.now().toUtc();
  }

  void removePresence(String catId, WebSocket socket) {
    final current = presenceByCatId[catId];
    if (current == null || current.socket == socket) {
      presenceByCatId.remove(catId);
      lastActivity.remove(catId);
    }
  }

  void cleanup() {
    final now = DateTime.now().toUtc();
    challenges.removeWhere((_, challenge) => now.isAfter(challenge.expiresAt));

    final stale = <String>[];
    for (final entry in lastActivity.entries) {
      if (now.difference(entry.value) > _presenceInactivityLimit) {
        stale.add(entry.key);
      }
    }

    for (final catId in stale) {
      final presence = presenceByCatId.remove(catId);
      lastActivity.remove(catId);
      try {
        presence?.socket.close(WebSocketStatus.goingAway, 'inactive');
      } catch (_) {}
    }
  }
}

class RateLimiter {
  RateLimiter({
    required this.maxEvents,
    required this.window,
  });

  final int maxEvents;
  final Duration window;
  final Map<String, List<DateTime>> _events = {};

  bool allow(String key) {
    final now = DateTime.now().toUtc();
    final list = _events.putIfAbsent(key, () => <DateTime>[]);
    list.removeWhere((time) => now.difference(time) >= window);
    final allowed = list.length < maxEvents;
    if (allowed) list.add(now);

    // Prevent indefinite growth from one-off IPs/CAT IDs.
    if (_events.length > 5000) {
      _events.removeWhere((_, times) => times.isEmpty);
    }
    return allowed;
  }
}
