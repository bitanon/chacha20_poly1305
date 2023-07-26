// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'byte_sink.dart';

abstract class ByteBlockSink<T> implements ByteSink<T> {
  int _pos = 0;
  bool _ready = true;
  bool _closed = false;
  late final T _result;
  late final Uint8List _chunk;

  /// A sink that accepts data as list of bytes or stream of bytes and handles
  /// it as a chunk.
  ///
  /// Parameters:
  /// - The [memory] parameter defines how much space to occupy for the chunk.
  ByteBlockSink({
    int? memory,
  }) {
    _chunk = Uint8List(memory ?? blockLength);
  }

  /// Length of the block in bytes
  int get blockLength;

  @override
  bool get isClosed => _closed;

  @override
  bool get isReady => _ready;

  /// Process a [chunk] of bytes.
  ///
  /// The [length] is generally equal to the [blockLength], except for the
  /// the final chunk, where it can be less than the [blockLength].
  void $process(Uint8List chunk, int length);

  /// Finalizes the sink with the final [chunk] of [length] bytes.
  ///
  /// It should return the result of the sink.
  T $finalize(Uint8List chunk, int length);

  @override
  void add(int data) {
    throw UnimplementedError('Single byte is not allowed');
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
      _chunk[_pos++] = x;
      if (_pos == blockLength) {
        $process(_chunk, _pos);
        _pos = 0;
      }
    }
  }

  @override
  Future<void> addStream(Stream<int> stream) async {
    if (!_ready) {
      throw StateError('The sink is not ready');
    }
    if (_closed) {
      throw StateError('The consumer is already closed');
    }
    _ready = false;
    await for (int x in stream) {
      _chunk[_pos++] = x;
      if (_pos == blockLength) {
        $process(_chunk, _pos);
        _pos = 0;
      }
    }
    _ready = true;
  }

  @override
  T close() {
    if (_closed) return _result;
    if (!_ready) {
      throw StateError('The sink is not ready');
    }
    _result = $finalize(_chunk, _pos);
    _closed = true;
    return _result;
  }
}
