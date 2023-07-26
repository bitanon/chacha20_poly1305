// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:chacha20_poly1305/src/core/byte_sink.dart';
import 'package:chacha20_poly1305/src/core/byte_transformer.dart';

import 'algorithms/poly1305.dart';

/// A wrapper around the [Poly1305Sink] for easy access
class Poly1305 extends ByteTransformer<Uint8List> {
  final List<int> key;

  /// Creates a new instance for [Poly1305] authentication.
  ///
  /// Parameters:
  /// - [key] is required. It can be either 16 bytes or 32 bytes. If [key] is
  ///   32 bytes, the last 16 bytes is used to generate MAC, and first 16 bytes
  ///   is used as the secret key. Otherwise, if [key] is 16 bytes, it is used
  ///   for secret key only.
  ///
  /// **Warning**:
  /// This algorithm is designed to ensure unforgeability of a message with a
  /// random [key]. One [key] can only be used to authenticate only one
  /// message. Authenticating multiple messages using the same [key] could
  /// allow for forgeries.
  const Poly1305(this.key);

  @override
  ByteSink<Uint8List> createSink() => Poly1305Sink(key);
}

/// Computes the MAC of the [message] by the [key] if it is 32 bytes long, or
/// signs the [message] with the [key] if it is 16 bytes long, using the
/// Poly-1305 algorithm.
///
/// Parameters:
/// - [key] is required and must contain exactly 16 or 32 bytes.
/// - [message] is a variable-length list of bytes
///
/// **Warning**:
/// The algorithm is designed to ensure unforgeability of a message with a
/// random [key]. One [key] can only be used to authenticate only one
/// message. Authenticating multiple messages using the same [key] could
/// allow for forgeries.
///
/// See also:
/// - [poly1305] to generate unsigned MACs.
/// - [The Poly1305 Algorithms][pdf], the original paper on the Poly1305.
/// - [RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols][rfc8439].
///
/// [pdf]: https://cr.yp.to/mac/poly1305-20050329.pdf
/// [rfc8439]: https://www.ietf.org/rfc/rfc8439.html
@pragma('vm:prefer-inline')
Uint8List poly1305(List<int> key, List<int> message) =>
    Poly1305(key).convert(message);

@pragma('vm:prefer-inline')
Stream<Uint8List> poly1305stream(List<int> key, Stream<int> message) =>
    Poly1305(key).bind(message);
