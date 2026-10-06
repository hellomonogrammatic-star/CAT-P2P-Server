import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:cryptography/cryptography.dart';

final _catIdPattern =
    RegExp(r'^CAT-[A-Z0-9]{4}-[A-Z0-9]{4}$');

final _pendingChallenges =
    <String, _Challenge>{};

final _online =
    <String, _OnlineCat>{};

Future<void> main(List<String> args) async {
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
    'Mode: ephemeral presence + signaling (no persistent CAT data)',
  );

  stdout.writeln(
    'Presence expires only when the WebSocket connection closes.',
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
    try {
      await _handle(request);
    } catch (error) {
      stderr.writeln(
        'Request error: $error',
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
            'cat-step3',
        'mode':
            'ephemeral-presence-and-signaling',
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

    final catId =
        body?['catId']
                ?.toString()
                .trim()
                .toUpperCase() ??
            '';

    if (!_catIdPattern
        .hasMatch(catId)) {
      _respond(
        request,
        HttpStatus.badRequest,
        {
          'message':
              'Invalid CAT ID format',
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
  // LOOKUP ONLINE CAT
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

    if (!_catIdPattern
        .hasMatch(catId)) {
      _respond(
        request,
        HttpStatus.badRequest,
        {
          'message':
              'Invalid CAT ID format',
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
      'message': 'Not found',
    },
  );
}

Future<void> _handleSocket(
  WebSocket socket,
) async {
  // WebSocket-level liveness.
  //
  // This is NOT a 45-second CAT expiry.
  // The server removes presence when the actual socket closes.
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

      final message =
          _decodeObject(raw);

      if (message == null) {
        continue;
      }

      final type =
          message['type']
              ?.toString();

      // ----------------------------------------------------------
      // REGISTRATION
      // ----------------------------------------------------------

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

      // ----------------------------------------------------------
      // EVERYTHING ELSE REQUIRES REGISTRATION
      // ----------------------------------------------------------

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

      // ----------------------------------------------------------
      // OPTIONAL HEARTBEAT
      //
      // Presence does not depend on this anymore.
      // It is accepted only as an explicit keepalive message.
      // ----------------------------------------------------------

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

      // ----------------------------------------------------------
      // TRANSIENT SIGNAL
      // ----------------------------------------------------------

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
      'Socket error: $error',
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

  if (!_catIdPattern
      .hasMatch(catId)) {
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

  if (signingPublicKeyBytes
              .length !=
          32 ||
      exchangePublicKeyBytes
              .length !=
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
    'CAT-PRESENCE\n$catId\n$nonce',
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
        fingerprint,
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

  if (!_catIdPattern
          .hasMatch(target) ||
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

  final payload =
      Map<String, dynamic>
          .from(
    rawPayload,
  );

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

    return decoded
        is Map<String, dynamic>
        ? decoded
        : null;
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

  request.response
      .close();
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

    return decoded
        is Map<String, dynamic>
        ? decoded
        : null;
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
