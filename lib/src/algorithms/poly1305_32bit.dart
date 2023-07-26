// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:chacha20_poly1305/src/core/byte_sink.dart';

// clamp = 0x0ffffffc0ffffffc0ffffffc0fffffff
const List<int> _clamp = <int>[
  0xff, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, //
  0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f,
];

/// This implementation is derived from the [The Poly1305 Algorithms] section
/// of the [ChaCha20 and Poly1305 for IETF Protocols][rfc] document.
///
/// [rfc]: https://www.ietf.org/rfc/rfc8439.html
class Poly1305Sink implements ByteSink<Uint8List> {
  // secret key: r
  BigInt _r = BigInt.zero;
  // authentication key: s
  BigInt _s = BigInt.zero;
  // accumulator: a
  BigInt _h = BigInt.zero;
  // constants
  final _m = BigInt.two.pow(128);
  final _p = BigInt.two.pow(130) - BigInt.from(5);
  // chunk
  int _pos = 0;
  BigInt _n = BigInt.zero;
  // final
  bool _ready = true;
  bool _closed = false;
  late final Uint8List _result;

  Poly1305Sink(List<int> key) {
    if (key.length != 16 && key.length != 32) {
      throw ArgumentError('The key must be either 16 or 32 bytes');
    }

    // r = key[15..0] & 0x0ffffffc0ffffffc0ffffffc0fffffff
    for (int i = 15; i >= 0; i--) {
      _r <<= 8;
      _r += BigInt.from(key[i] & _clamp[i]);
    }

    // s = key[16..31]
    if (key.length == 32) {
      for (int i = 31; i >= 16; i--) {
        _s <<= 8;
        _s += BigInt.from(key[i]);
      }
    }
  }

  @override
  bool get isReady => _ready;

  @override
  bool get isClosed => _closed;

  @override
  void add(int data) {
    throw UnimplementedError();
  }

  @override
  void addAll(Iterable<int> data) {
    if (_closed) {
      throw StateError('The sink is already closed');
    }
    if (!_ready) {
      throw StateError('The sink is not ready');
    }
    for (int x in data) {
      if (_pos == 16) {
        _n += BigInt.one << 128;
        _h = ((_h + _n) * _r) % _p;
        _n = BigInt.zero;
        _pos = 0;
      }
      _n += BigInt.from(x) << (_pos << 3);
      _pos++;
    }
  }

  @override
  Future<void> addStream(Stream<int> stream) async {
    if (_closed) {
      throw StateError('The consumer is already closed');
    }
    if (!_ready) {
      throw StateError('The sink is not ready');
    }
    _ready = false;
    await for (int x in stream) {
      if (_pos == 16) {
        _n += BigInt.one << 128;
        _h = ((_h + _n) * _r) % _p;
        _n = BigInt.zero;
        _pos = 0;
      }
      _n += BigInt.from(x) << (_pos << 3);
      _pos++;
    }
    _ready = true;
  }

  @override
  Uint8List close() {
    if (_closed) return _result;

    if (!_ready) {
      throw StateError('The sink is not ready');
    }

    // remaining bytes
    if (_pos > 0) {
      _n += BigInt.one << (_pos << 3);
      _h = ((_h + _n) * _r) % _p;
    }

    _h += _s;

    _result = Uint32List.fromList([
      (_h % _m).toUnsigned(32).toInt(),
      ((_h >> 32) % _m).toUnsigned(32).toInt(),
      ((_h >> 64) % _m).toUnsigned(32).toInt(),
      ((_h >> 96) % _m).toUnsigned(32).toInt(),
    ]).buffer.asUint8List();

    _closed = true;
    return _result;
  }
}
