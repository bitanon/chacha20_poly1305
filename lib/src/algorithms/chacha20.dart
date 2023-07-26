// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:chacha20_poly1305/src/utils.dart';

const int _mask32 = 0xFFFFFFFF;

class ChaCha20 {
  final int counter;
  final List<int> key;
  final List<int> nonce;

  const ChaCha20({
    this.counter = 1,
    required this.key,
    required this.nonce,
  });

  Iterable<int> convert(Iterable<int> data) sync* {
    final key32 = toBytes(key).buffer.asUint32List();
    final nonce32 = toBytes(nonce).buffer.asUint32List();
    if (key32.lengthInBytes != 32) {
      throw ArgumentError('The key should be 32 bytes');
    }
    if (nonce32.lengthInBytes != 12) {
      throw ArgumentError('The nonce should be 12 bytes');
    }

    int pos = 0;
    int nos = counter;
    final state = Uint32List(16);
    final state8 = state.buffer.asUint8List();

    for (int x in data) {
      if (pos == 0 || pos == 64) {
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        state[4] = key32[0];
        state[5] = key32[1];
        state[6] = key32[2];
        state[7] = key32[3];
        state[8] = key32[4];
        state[9] = key32[5];
        state[10] = key32[6];
        state[11] = key32[7];
        state[12] = nos++;
        state[13] = nonce32[0];
        state[14] = nonce32[1];
        state[15] = nonce32[2];
        _round(state);
        pos = 0;
      }
      yield x ^ state8[pos++];
    }
  }

  @pragma('vm:prefer-inline')
  static int _rotl32(int x, int n) =>
      (((x << n) & _mask32) ^ ((x & _mask32) >>> (32 - n)));

  static void _round(Uint32List state) {
    int i;
    int s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15;
    s0 = state[0];
    s1 = state[1];
    s2 = state[2];
    s3 = state[3];
    s4 = state[4];
    s5 = state[5];
    s6 = state[6];
    s7 = state[7];
    s8 = state[8];
    s9 = state[9];
    s10 = state[10];
    s11 = state[11];
    s12 = state[12];
    s13 = state[13];
    s14 = state[14];
    s15 = state[15];
    for (i = 0; i < 10; ++i) {
      // _round(state, 0, 4, 8, 12);
      s0 += s4;
      s12 = _rotl32(s12 ^ s0, 16);
      s8 += s12;
      s4 = _rotl32(s4 ^ s8, 12);
      s0 += s4;
      s12 = _rotl32(s12 ^ s0, 8);
      s8 += s12;
      s4 = _rotl32(s4 ^ s8, 7);
      // _round(state, 1, 5, 9, 13);
      s1 += s5;
      s13 = _rotl32(s13 ^ s1, 16);
      s9 += s13;
      s5 = _rotl32(s5 ^ s9, 12);
      s1 += s5;
      s13 = _rotl32(s13 ^ s1, 8);
      s9 += s13;
      s5 = _rotl32(s5 ^ s9, 7);
      // _round(state, 2, 6, 10, 14);
      s2 += s6;
      s14 = _rotl32(s14 ^ s2, 16);
      s10 += s14;
      s6 = _rotl32(s6 ^ s10, 12);
      s2 += s6;
      s14 = _rotl32(s14 ^ s2, 8);
      s10 += s14;
      s6 = _rotl32(s6 ^ s10, 7);
      // _round(state, 3, 7, 11, 15);
      s3 += s7;
      s15 = _rotl32(s15 ^ s3, 16);
      s11 += s15;
      s7 = _rotl32(s7 ^ s11, 12);
      s3 += s7;
      s15 = _rotl32(s15 ^ s3, 8);
      s11 += s15;
      s7 = _rotl32(s7 ^ s11, 7);
      // _round(state, 0, 5, 10, 15);
      s0 += s5;
      s15 = _rotl32(s15 ^ s0, 16);
      s10 += s15;
      s5 = _rotl32(s5 ^ s10, 12);
      s0 += s5;
      s15 = _rotl32(s15 ^ s0, 8);
      s10 += s15;
      s5 = _rotl32(s5 ^ s10, 7);
      // _round(state, 1, 6, 11, 12);
      s1 += s6;
      s12 = _rotl32(s12 ^ s1, 16);
      s11 += s12;
      s6 = _rotl32(s6 ^ s11, 12);
      s1 += s6;
      s12 = _rotl32(s12 ^ s1, 8);
      s11 += s12;
      s6 = _rotl32(s6 ^ s11, 7);
      // _round(state, 2, 7, 8, 13);
      s2 += s7;
      s13 = _rotl32(s13 ^ s2, 16);
      s8 += s13;
      s7 = _rotl32(s7 ^ s8, 12);
      s2 += s7;
      s13 = _rotl32(s13 ^ s2, 8);
      s8 += s13;
      s7 = _rotl32(s7 ^ s8, 7);
      // _round(state, 3, 4, 9, 14);
      s3 += s4;
      s14 = _rotl32(s14 ^ s3, 16);
      s9 += s14;
      s4 = _rotl32(s4 ^ s9, 12);
      s3 += s4;
      s14 = _rotl32(s14 ^ s3, 8);
      s9 += s14;
      s4 = _rotl32(s4 ^ s9, 7);
    }
    state[0] += s0;
    state[1] += s1;
    state[2] += s2;
    state[3] += s3;
    state[4] += s4;
    state[5] += s5;
    state[6] += s6;
    state[7] += s7;
    state[8] += s8;
    state[9] += s9;
    state[10] += s10;
    state[11] += s11;
    state[12] += s12;
    state[13] += s13;
    state[14] += s14;
    state[15] += s15;
  }
}
