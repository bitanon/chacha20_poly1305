// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';

abstract class ByteSink<T> {
  /// A sink that accepts data as list of bytes or stream of bytes.
  const ByteSink();

  /// Whether the sink is already closed
  bool get isClosed;

  /// Whether the sink is ready to accept new data
  bool get isReady;

  /// Adds [data] to the sink.
  ///
  /// Exceptions:
  /// - [StateError] if called after [close] or during [addStream].
  void add(int data);

  /// Closes the sink and stops accepting new data.
  ///
  /// Returns the final result. Calling the method multiple times will return
  /// the same result every time.
  ///
  /// Exceptions:
  /// - [StateError] if called during [addStream].
  T close();

  /// Consumes the elements of [list].
  ///
  /// Exceptions:
  /// - [StateError] if called after [close] or during [addStream].
  void addAll(Iterable<int> list) {
    for (int data in list) {
      add(data);
    }
  }

  /// Consumes the elements of [stream].
  ///
  /// Listens on [stream] and does something for each event.
  ///
  /// Returns a future which is completed when the stream is done being added,
  /// and the consumer is ready to accept a new stream.
  ///
  /// Exceptions:
  /// - Any errors while listening to the [stream].
  /// - [StateError] if called after [close] or during another [addStream].
  Future<void> addStream(Stream<int> stream) async {
    await for (int data in stream) {
      add(data);
    }
  }
}
