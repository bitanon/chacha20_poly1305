// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';

import 'byte_sink.dart';

/// A wrapper around the [ByteSink] for transforming streams
abstract class ByteTransformer<T> implements StreamTransformer<int, T> {
  const ByteTransformer();

  /// Creates a new [ByteSink] for transformation
  @pragma('vm:prefer-inline')
  ByteSink<T> createSink();

  @override
  StreamTransformer<RS, RT> cast<RS, RT>() => StreamTransformer.castFrom(this);

  /// Transforms a list of bytes
  @pragma('vm:prefer-inline')
  T convert(Iterable<int> message) {
    var sink = createSink();
    sink.addAll(message);
    return sink.close();
  }

  /// Transforms a [stream] of bytes
  @override
  @pragma('vm:prefer-inline')
  Stream<T> bind(Stream<int> stream) async* {
    var sink = createSink();
    await sink.addStream(stream);
    yield sink.close();
  }

  /// Transforms a [stream] with list of bytes
  @pragma('vm:prefer-inline')
  Stream<T> stream(Stream<Iterable<int>> stream) async* {
    var sink = createSink();
    await sink.addStream(stream.expand((e) => e));
    yield sink.close();
  }
}
