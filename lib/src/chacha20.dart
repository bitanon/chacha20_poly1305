// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib_codecs/hashlib_codecs.dart';

const int _mask32 = 0xFFFFFFFF;

class ChaCha20 {
  final int counter;
  final Uint8List key;
  final Uint8List nonce;
  final Uint32List _state = Uint32List(16);
  late final Uint32List _key32 = key.buffer.asUint32List();
  late final Uint32List _nonce32 = nonce.buffer.asUint32List();
  late final Uint8List _state8 = _state.buffer.asUint8List();

  ChaCha20({
    this.counter = 1,
    required this.key,
    required this.nonce,
  }) {
    if (key.lengthInBytes != 32) {
      throw ArgumentError('The key should be 32 bytes');
    }
    if (nonce.lengthInBytes != 12) {
      throw ArgumentError('The nonce should be 12 bytes');
    }
  }

  void reset(int p) {
    _state[0] = 0x61707865;
    _state[1] = 0x3320646e;
    _state[2] = 0x79622d32;
    _state[3] = 0x6b206574;
    _state[4] = _key32[0];
    _state[5] = _key32[1];
    _state[6] = _key32[2];
    _state[7] = _key32[3];
    _state[8] = _key32[4];
    _state[9] = _key32[5];
    _state[10] = _key32[6];
    _state[11] = _key32[7];
    _state[12] = p;
    _state[13] = _nonce32[0];
    _state[14] = _nonce32[1];
    _state[15] = _nonce32[2];
  }

  Uint8List encrypt(List<int> message) {
    int i, j, p;
    final out = Uint8List.fromList(message);
    p = counter;
    for (j = 0; j + 64 < message.length; j += 64, p++) {
      reset(p);
      _round(_state);
      print(_state.map((e) => e.toRadixString(16).padLeft(8, '0')).join(' '));
      for (i = 0; i < 64; ++i) {
        out[j + i] ^= _state8[i];
      }
    }
    if (j < message.length) {
      reset(p);
      _round(_state);
      for (i = 0; j + i < message.length; ++i) {
        out[j + i] ^= _state8[i];
      }
    }
    return out;
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

void main() {
  var key = fromHex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  var nonce = fromHex("000000000000004a00000000");
  var message =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
  print(toHex(message.codeUnits));
  final chacha = ChaCha20(
    key: key,
    nonce: nonce,
    counter: 1,
  );
  var cipher = chacha.encrypt(message.codeUnits);
  print(toHex(cipher));
  var plain = chacha.encrypt(cipher);
  print(String.fromCharCodes(plain));
}
