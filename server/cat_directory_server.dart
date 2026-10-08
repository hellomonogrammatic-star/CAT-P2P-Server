import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:cryptography/cryptography.dart';

const String _serverVersion =
    'cat-step4-cat-id-fix-v2';

const int _maxSocketFrameBytes =
    512 * 1024;

const int _maxSignalPayloadBytes =
    256 * 1024;

const int _turnCredentialTtlSeconds =
    86400;

final _pendingChallenges =
    <String, _Challenge>{};

final _online =
    <String, _OnlineCat>{};

Future<void> main(
  List<String> args,
) async {
  final port =
      int.tryParse(
            Platform.environment['PORT'] ?? '',
          ) ??
          int.tryParse(
            _argValue(
                  args,
                  '--port',
                ) ??
                '',
          ) ??
          10000;

  final server =
      await HttpServer.bind(
    InternetAddress.anyIPv4,
    port,
  );

  stdout.writeln(
    'CAT public server listening on http://0.0.0.0:$port',
  );

  stdout.writeln(
    'Server version: $_serverVersion',
  );

  stdout.writeln(
    'Mode: concurrent ephemeral presence + WebSocket signaling',
  );

  stdout.writeln(
    'Presence exists while the authenticated WebSocket is alive.',
  );

  Timer.periodic(
    const Duration(seconds: 30),
    (_) => _expireChallenges(),
  );

  final shutdown =
      Completer<void>();

  if (Platform.isWindows ||
      Platform.isLinux ||
      Platform.isMacOS) {
    ProcessSignal.sigint
        .watch()
        .listen((_) {
      if (!shutdown.isCompleted) {
        shutdown.complete();
      }
    });
  }

  await Future.any([
    _serve(server),
    shutdown.future,
  ]);

  await server.close(
    force: true,
  );

  for (final peer
      in _online.values.toList()) {
    try {
      await peer.socket.close(
        WebSocketStatus.goingAway,
        'Server shutting down',
      );
    } catch (_) {}
  }

  _online.clear();
}

Future<void> _serve(
  HttpServer server,
) async {
  await for (final request
      in server) {
    unawaited(
      _handleSafely(request),
    );
  }
}

Future<void> _handleSafely(
  HttpRequest request,
) async {
  try {
    await _handle(request);
  } catch (error, stack) {
    stderr.writeln(
      'Request error: $error',
    );

    stderr.writeln(
      stack,
    );

    try {
      request.response
        ..statusCode =
            HttpStatus.internalServerError
        ..headers.contentType =
            ContentType.json
        ..write(
          jsonEncode({
            'message':
                'Internal server error',
          }),
        );

      await request.response.close();
    } catch (_) {}
  }
}

Future<void> _handle(
  HttpRequest request,
) async {
  _commonHeaders(
    request.response,
  );

  if (request.method == 'OPTIONS') {
    request.response.statusCode =
        HttpStatus.noContent;

    await request.response.close();

    return;
  }

  final path =
      request.uri.path;

  // ------------------------------------------------------------
  // HEALTH
  // ------------------------------------------------------------

  if (request.method == 'GET' &&
      path == '/health') {
    _respond(
      request,
      HttpStatus.ok,
      {
        'ok': true,
        'service':
            'cat-step4',
        'version':
            _serverVersion,
        'catIdFormat':
            'CAT-XXXX-XXXX',
        'mode':
            'concurrent-ephemeral-presence-and-signaling',
      },
    );

    return;
  }

  // ------------------------------------------------------------
  // PRESENCE CHALLENGE
  // ------------------------------------------------------------

  if (request.method == 'POST' &&
      path ==
          '/v1/presence/challenge') {
    final body =
        await _readJson(request);

    if (body == null) {
      _respond(
        request,
        HttpStatus.badRequest,
        {
          'message':
              'Invalid JSON body',
          'version':
              _serverVersion,
        },
      );

      return;
    }

    final catId =
        body['catId']
                ?.toString()
                .trim()
                .toUpperCase() ??
            '';

    if (!_isValidCatId(catId)) {
      _respond(
        request,
        HttpStatus.badRequest,
        {
          'message':
              'Invalid CAT ID format',
          'version':
              _serverVersion,
        },
      );

      return;
    }

    final nonceBytes =
        List<int>.generate(
      32,
      (_) => Random.secure()
          .nextInt(256),
    );

    final nonce =
        base64UrlEncode(
      nonceBytes,
    );

    _pendingChallenges[catId] =
        _Challenge(
      nonce: nonce,
      expiresAt:
          DateTime.now()
              .toUtc()
              .add(
                const Duration(
                  minutes: 1,
                ),
              ),
    );

    _respond(
      request,
      HttpStatus.ok,
      {
        'nonce': nonce,
      },
    );

    return;
  }

  // ------------------------------------------------------------
  // PRESENCE LOOKUP
  // ------------------------------------------------------------

  if (request.method == 'GET' &&
      path == '/v1/presence') {
    final catId =
        request
                .uri
                .queryParameters['catId']
                ?.trim()
                .toUpperCase() ??
            '';

    if (!_isValidCatId(catId)) {
      _respond(
        request,
        HttpStatus.badRequest,
        {
          'message':
              'Invalid CAT ID format',
          'version':
              _serverVersion,
        },
      );

      return;
    }

    final peer =
        _online[catId];

    if (peer == null ||
        peer.socket.readyState !=
            WebSocket.open) {
      _respond(
        request,
        HttpStatus.notFound,
        {
          'online': false,
          'catId': catId,
        },
      );

      return;
    }

    _respond(
      request,
      HttpStatus.ok,
      {
        'online': true,
        'catId':
            peer.catId,
        'signingPublicKey':
            peer.signingPublicKey,
        'exchangePublicKey':
            peer.exchangePublicKey,
        'publicFingerprint':
            peer.publicFingerprint,
      },
    );

    return;
  }

  // ------------------------------------------------------------
  // ONLINE COUNT
  // ------------------------------------------------------------

  if (request.method == 'GET' &&
      path ==
          '/v1/presence/count') {
    _respond(
      request,
      HttpStatus.ok,
      {
        'online':
            _online.length,
      },
    );

    return;
  }

  // ------------------------------------------------------------
  // WEB SOCKET
  // ------------------------------------------------------------

  if (request.method == 'GET' &&
      path == '/v1/signal' &&
      WebSocketTransformer
          .isUpgradeRequest(
        request,
      )) {
    try {
      final socket =
          await WebSocketTransformer
              .upgrade(request);

      await _handleSocket(
        socket,
      );
    } catch (error) {
      stderr.writeln(
        'WebSocket upgrade error: $error',
      );
    }

    return;
  }

  _respond(
    request,
    HttpStatus.notFound,
    {
      'message':
          'Not found',
    },
  );
}

Future<void> _handleSocket(
  WebSocket socket,
) async {
  socket.pingInterval =
      const Duration(
    seconds: 20,
  );

  _PendingSocketRegistration?
      registration;

  try {
    await for (final dynamic raw
        in socket) {
      if (raw is! String) {
        continue;
      }

      if (raw.length >
          _maxSocketFrameBytes) {
        _send(
          socket,
          {
            'type':
                'presence',
            'status':
                'rejected',
            'message':
                'Socket frame too large',
          },
        );

        try {
          await socket.close(
            WebSocketStatus
                .messageTooBig,
            'Socket frame too large',
          );
        } catch (_) {}

        return;
      }

      final message =
          _decodeObject(raw);

      if (message == null) {
        continue;
      }

      final type =
          message['type']
              ?.toString();

      if (type ==
          'presence.register') {
        if (registration != null) {
          _send(
            socket,
            {
              'type':
                  'presence',
              'status':
                  'rejected',
              'message':
                  'CAT presence already registered on this socket',
            },
          );

          continue;
        }

        final result =
            await _registerSocket(
          socket,
          message,
        );

        if (result != null) {
          registration =
              result;
        }

        continue;
      }

      if (registration == null) {
        _send(
          socket,
          {
            'type':
                'presence',
            'status':
                'rejected',
            'message':
                'Register CAT presence before signaling',
          },
        );

        continue;
      }

      if (type ==
          'turn.credentials.request') {
        try {
          final credentials =
              await _generateTurnCredentials();

          _send(
            socket,
            {
              'type':
                  'turn.credentials',
              'iceServers':
                  credentials,
            },
          );
        } catch (error) {
          stderr.writeln(
            'TURN credential generation failed for ${registration.catId}: $error',
          );

          _send(
            socket,
            {
              'type':
                  'turn.credentials.error',
              'message':
                  'TURN credentials unavailable',
            },
          );
        }

        continue;
      }

      if (type ==
          'presence.heartbeat') {
        _send(
          socket,
          {
            'type':
                'presence.heartbeat_ack',
          },
        );

        continue;
      }

      if (type ==
          'signal.send') {
        _routeSignal(
          socket,
          registration.catId,
          message,
        );

        continue;
      }
    }
  } catch (error) {
    stderr.writeln(
      'CAT socket error: $error',
    );
  } finally {
    if (registration !=
        null) {
      final current =
          _online[
              registration.catId];

      if (current != null &&
          identical(
            current.socket,
            socket,
          )) {
        _online.remove(
          registration.catId,
        );
      }
    }
  }
}

Future<_PendingSocketRegistration?>
    _registerSocket(
  WebSocket socket,
  Map<String, dynamic>
      message,
) async {
  final catId =
      message['catId']
              ?.toString()
              .trim()
              .toUpperCase() ??
          '';

  final signingPublicKeyEncoded =
      message['signingPublicKey']
              ?.toString() ??
          '';

  final exchangePublicKeyEncoded =
      message['exchangePublicKey']
              ?.toString() ??
          '';

  final fingerprint =
      message['publicFingerprint']
              ?.toString() ??
          '';

  final nonce =
      message['nonce']
              ?.toString() ??
          '';

  final signatureEncoded =
      message['signature']
              ?.toString() ??
          '';

  if (!_isValidCatId(catId)) {
    _reject(
      socket,
      'Invalid CAT ID format',
    );

    return null;
  }

  final challenge =
      _pendingChallenges
          .remove(catId);

  if (challenge == null ||
      DateTime.now()
          .toUtc()
          .isAfter(
            challenge.expiresAt,
          )) {
    _reject(
      socket,
      'Presence challenge expired',
    );

    return null;
  }

  if (challenge.nonce != nonce) {
    _reject(
      socket,
      'Invalid presence challenge',
    );

    return null;
  }

  late List<int>
      signingPublicKeyBytes;

  late List<int>
      exchangePublicKeyBytes;

  late List<int>
      signatureBytes;

  try {
    signingPublicKeyBytes =
        base64Url.decode(
      signingPublicKeyEncoded,
    );

    exchangePublicKeyBytes =
        base64Url.decode(
      exchangePublicKeyEncoded,
    );

    signatureBytes =
        base64Url.decode(
      signatureEncoded,
    );
  } catch (_) {
    _reject(
      socket,
      'Invalid key encoding',
    );

    return null;
  }

  if (signingPublicKeyBytes.length !=
          32 ||
      exchangePublicKeyBytes.length !=
          32 ||
      signatureBytes.length !=
          64) {
    _reject(
      socket,
      'Invalid CAT public key material',
    );

    return null;
  }

  final publicKey =
      SimplePublicKey(
    signingPublicKeyBytes,
    type:
        KeyPairType.ed25519,
  );

  final signedMessage =
      utf8.encode(
    'CAT-PRESENCE\n'
    '$catId\n'
    '$nonce',
  );

  bool validProof =
      false;

  try {
    validProof =
        await Ed25519().verify(
      signedMessage,
      signature:
          Signature(
        signatureBytes,
        publicKey:
            publicKey,
      ),
    );
  } catch (_) {
    validProof =
        false;
  }

  if (!validProof) {
    _reject(
      socket,
      'Invalid CAT identity proof',
    );

    return null;
  }

  final expectedFingerprint =
      _fingerprint(
    signingPublicKeyBytes,
  );

  if (fingerprint.isNotEmpty &&
      fingerprint.toUpperCase() !=
          expectedFingerprint) {
    _reject(
      socket,
      'Invalid CAT fingerprint',
    );

    return null;
  }

  final previous =
      _online[catId];

  if (previous != null &&
      !identical(
        previous.socket,
        socket,
      )) {
    try {
      await previous.socket
          .close(
        WebSocketStatus
            .policyViolation,
        'CAT opened on another session',
      );
    } catch (_) {}
  }

  final peer =
      _OnlineCat(
    catId: catId,
    signingPublicKey:
        signingPublicKeyEncoded,
    exchangePublicKey:
        exchangePublicKeyEncoded,
    publicFingerprint:
        expectedFingerprint,
    socket: socket,
  );

  _online[catId] =
      peer;

  _send(
    socket,
    {
      'type':
          'presence',
      'status':
          'online',
      'catId':
          catId,
    },
  );

  return _PendingSocketRegistration(
    catId,
  );
}

Future<List<Map<String, dynamic>>>
    _generateTurnCredentials() async {
  final keyId =
      Platform.environment[
                  'CLOUDFLARE_TURN_KEY_ID']
              ?.trim() ??
          '';

  final apiToken =
      Platform.environment[
                  'CLOUDFLARE_TURN_API_TOKEN']
              ?.trim() ??
          '';

  if (keyId.isEmpty ||
      apiToken.isEmpty) {
    throw StateError(
      'Cloudflare TURN server credentials are not configured',
    );
  }

  final endpoint =
      Uri.parse(
    'https://rtc.live.cloudflare.com/v1/turn/keys/'
    '$keyId/credentials/generate-ice-servers',
  );

  final client =
      HttpClient();

  client.connectionTimeout =
      const Duration(
    seconds: 10,
  );

  try {
    final request =
        await client.postUrl(
      endpoint,
    );

    request.headers
      ..contentType =
          ContentType.json
      ..set(
        HttpHeaders.authorizationHeader,
        'Bearer $apiToken',
      )
      ..set(
        HttpHeaders.acceptHeader,
        'application/json',
      );

    request.write(
      jsonEncode({
        'ttl':
            _turnCredentialTtlSeconds,
      }),
    );

    final response =
        await request.close().timeout(
      const Duration(
        seconds: 10,
      ),
    );

    final body =
        await response
            .transform(
              utf8.decoder,
            )
            .join()
            .timeout(
          const Duration(
            seconds: 10,
          ),
        );

    final decoded =
        _decodeObject(body);

    if (response.statusCode !=
            HttpStatus.created ||
        decoded == null ||
        decoded['iceServers'] is! List) {
      throw StateError(
        'Cloudflare TURN API returned HTTP ${response.statusCode}',
      );
    }

    final rawServers =
        decoded['iceServers'] as List;

    final servers =
        rawServers
            .whereType<Map>()
            .map(
              (item) =>
                  Map<String, dynamic>.from(
                item,
              ),
            )
            .where(
              (item) =>
                  item['urls'] != null,
            )
            .toList();

    if (servers.isEmpty) {
      throw StateError(
        'Cloudflare TURN API returned no ICE servers',
      );
    }

    return servers;
  } finally {
    client.close(
      force: true,
    );
  }
}

void _routeSignal(
  WebSocket senderSocket,
  String senderCatId,
  Map<String, dynamic>
      message,
) {
  final target =
      message['to']
              ?.toString()
              .trim()
              .toUpperCase() ??
          '';

  final rawPayload =
      message['payload'];

  if (!_isValidCatId(target) ||
      rawPayload is! Map) {
    _send(
      senderSocket,
      {
        'type':
            'signal.error',
        'message':
            'Invalid signaling request',
      },
    );

    return;
  }

  final payload =
      Map<String, dynamic>.from(
    rawPayload,
  );

  try {
    final payloadBytes =
        utf8.encode(
      jsonEncode(payload),
    );

    if (payloadBytes.length >
        _maxSignalPayloadBytes) {
      _send(
        senderSocket,
        {
          'type':
              'signal.error',
          'message':
              'Signaling payload too large',
        },
      );

      return;
    }
  } catch (_) {
    _send(
      senderSocket,
      {
        'type':
            'signal.error',
        'message':
            'Invalid signaling payload',
      },
    );

    return;
  }

  final recipient =
      _online[target];

  if (recipient == null ||
      recipient.socket.readyState !=
          WebSocket.open) {
    _send(
      senderSocket,
      {
        'type':
            'signal.error',
        'to':
            target,
        'message':
            'TARGET CAT OFFLINE',
      },
    );

    return;
  }

  _send(
    recipient.socket,
    {
      'type':
          'signal',
      'from':
          senderCatId,
      'payload':
          payload,
    },
  );

  _send(
    senderSocket,
    {
      'type':
          'signal.sent',
      'to':
          target,
    },
  );
}

/// Validates exactly:
///
/// CAT-XXXX-XXXX
///
/// Each X must be A-Z or 0-9 after uppercasing.
bool _isValidCatId(
  String catId,
) {
  if (catId.length != 13) {
    return false;
  }

  if (catId.substring(0, 4) !=
      'CAT-') {
    return false;
  }

  if (catId.codeUnitAt(8) !=
      45) {
    return false;
  }

  for (int index = 4;
      index < 8;
      index++) {
    if (!_isAlphaNumeric(
      catId.codeUnitAt(index),
    )) {
      return false;
    }
  }

  for (int index = 9;
      index < 13;
      index++) {
    if (!_isAlphaNumeric(
      catId.codeUnitAt(index),
    )) {
      return false;
    }
  }

  return true;
}

bool _isAlphaNumeric(
  int codeUnit,
) {
  final upper =
      codeUnit >= 65 &&
      codeUnit <= 90;

  final digit =
      codeUnit >= 48 &&
      codeUnit <= 57;

  return upper || digit;
}

String _fingerprint(
  List<int> publicKeyBytes,
) {
  return publicKeyBytes
      .take(12)
      .map(
        (value) =>
            value
                .toRadixString(16)
                .padLeft(
                  2,
                  '0',
                ),
      )
      .join(':')
      .toUpperCase();
}

void _reject(
  WebSocket socket,
  String message,
) {
  _send(
    socket,
    {
      'type':
          'presence',
      'status':
          'rejected',
      'message':
          message,
    },
  );

  try {
    socket.close(
      WebSocketStatus
          .policyViolation,
      message,
    );
  } catch (_) {}
}

void _send(
  WebSocket socket,
  Map<String, dynamic>
      message,
) {
  try {
    if (socket.readyState ==
        WebSocket.open) {
      socket.add(
        jsonEncode(message),
      );
    }
  } catch (_) {}
}

void _expireChallenges() {
  final now =
      DateTime.now().toUtc();

  _pendingChallenges.removeWhere(
    (_, challenge) =>
        now.isAfter(
      challenge.expiresAt,
    ),
  );
}

Future<Map<String, dynamic>?>
    _readJson(
  HttpRequest request,
) async {
  final bytes =
      <int>[];

  await for (final chunk
      in request) {
    bytes.addAll(chunk);

    if (bytes.length >
        64 * 1024) {
      return null;
    }
  }

  if (bytes.isEmpty) {
    return null;
  }

  try {
    final decoded =
        jsonDecode(
      utf8.decode(bytes),
    );

    if (decoded is Map) {
      return Map<String, dynamic>.from(
        decoded,
      );
    }

    return null;
  } catch (_) {
    return null;
  }
}

void _respond(
  HttpRequest request,
  int status,
  Map<String, dynamic>
      body,
) {
  request.response
    ..statusCode = status
    ..headers.contentType =
        ContentType.json
    ..write(
      jsonEncode(body),
    );

  unawaited(
    request.response.close(),
  );
}

void _commonHeaders(
  HttpResponse response,
) {
  response.headers
    ..set(
      'access-control-allow-origin',
      '*',
    )
    ..set(
      'access-control-allow-methods',
      'GET,POST,OPTIONS',
    )
    ..set(
      'access-control-allow-headers',
      'content-type,accept',
    );
}

String? _argValue(
  List<String> args,
  String name,
) {
  final index =
      args.indexOf(name);

  if (index == -1 ||
      index + 1 >= args.length) {
    return null;
  }

  return args[index + 1];
}

Map<String, dynamic>?
    _decodeObject(
  dynamic body,
) {
  if (body is! String ||
      body.trim().isEmpty) {
    return null;
  }

  try {
    final decoded =
        jsonDecode(body);

    if (decoded is Map) {
      return Map<String, dynamic>.from(
        decoded,
      );
    }

    return null;
  } catch (_) {
    return null;
  }
}

class _Challenge {
  const _Challenge({
    required this.nonce,
    required this.expiresAt,
  });

  final String nonce;
  final DateTime expiresAt;
}

class _OnlineCat {
  const _OnlineCat({
    required this.catId,
    required this.signingPublicKey,
    required this.exchangePublicKey,
    required this.publicFingerprint,
    required this.socket,
  });

  final String catId;
  final String signingPublicKey;
  final String exchangePublicKey;
  final String publicFingerprint;
  final WebSocket socket;
}

class _PendingSocketRegistration {
  const _PendingSocketRegistration(
    this.catId,
  );

  final String catId;
}
