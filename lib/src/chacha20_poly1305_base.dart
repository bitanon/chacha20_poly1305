import 'package:chacha20_poly1305/src/algorithms/chacha20.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';

void main() async {
  var key = fromHex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  var nonce = fromHex("000000000000004a00000000");
  var message =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
  print(message);
  print(toHex(message.codeUnits));
  final chacha = ChaCha20(
    key: key,
    nonce: nonce,
    counter: 1,
  );
  var cipher = chacha.convert(message.codeUnits).toList();
  print(toHex(cipher));
  var plain = String.fromCharCodes(chacha.convert(cipher));
  print(plain);
  print(plain == message ? 'OK' : 'FAIL');
}
