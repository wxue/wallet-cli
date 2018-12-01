package org.tron.common.crypto.chacha20poly1305;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import org.apache.commons.lang3.ArrayUtils;
import org.tron.common.crypto.chacha20poly1305.ChaCha20.WrongKeySizeException;
import org.tron.common.crypto.chacha20poly1305.ChaCha20.WrongNonceSizeException;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;
import org.tron.common.utils.ZksnarkUtils;

public class ChaCha20Poly1305aead {

  public static class WrongPolyMac extends Exception {

  }

  public static byte[] pad16(int length) {
    if (length % 16 == 0) {
      return null;
    }
    length = 16 - length % 16;
    byte[] result = new byte[length];
    return result;
  }

  public static boolean chacha20poly1305_crypt(byte[] aad, byte[] key, byte[] nonce, byte[] dest,
      byte[] src, int is_encrypt)
      throws WrongKeySizeException, WrongNonceSizeException, WrongPolyMac {
    byte[] poly_key = new byte[32];
    byte[] zero = new byte[32];
    boolean r = false;

    ChaCha20 chaCha20 = new ChaCha20(key, nonce, 0);
    chaCha20.decrypt(poly_key, zero, zero.length);

    byte[] mac_data = null;
    byte[] aadpad = null;
    byte[] aadLen;
    if (!ArrayUtils.isEmpty(aad)) {
      aadpad = pad16(aad.length);
      aadLen = ByteArray.fromLong(aad.length);
      ZksnarkUtils.sort(aadLen);
      mac_data = aad;
      if (aadpad != null) {
        mac_data = ByteUtil.merge(mac_data, aadpad);
      }
    } else {
      aadLen = new byte[8];
    }

    byte[] cipher = Arrays.copyOfRange(src, 0, src.length - 16);
    byte[] cipherpad = pad16(cipher.length);
    byte[] cipherLen = ByteArray.fromLong(cipher.length);
    ZksnarkUtils.sort(cipherLen);
    if (mac_data == null) {
      mac_data = cipher;
    } else {
      mac_data = ByteUtil.merge(mac_data, cipher);
    }
    if (cipherpad != null) {
      mac_data = ByteUtil.merge(mac_data, cipherpad);
    }
    mac_data = ByteUtil.merge(mac_data, aadLen, cipherLen);

    byte[] tag = Poly1305.poly1305_auth(mac_data, mac_data.length, poly_key);
    byte[] tag0 = Arrays.copyOfRange(src, src.length - 16, src.length);
    if (!Arrays.equals(tag, tag0)) {
      throw new WrongPolyMac();
    }

    chaCha20 = new ChaCha20(key, nonce, 1);
    chaCha20.decrypt(dest, src, src.length - 16);
    return r;
  }

  public static void main(String[] args)
      throws WrongKeySizeException, WrongNonceSizeException, WrongPolyMac {
    ArrayList<String> textlist = new ArrayList<>();
    textlist.add(
        "db36fc036d24b930f0d08910cdd699c03891a282e9406ea12605267c4132eacadab8b081ca3cd551ed9e6f0a1118f5edb40104dd08e7847e811e459786927f1c949ad247dc9cc8d63409f85d357e45024c317dfc78a163ac7109217c8a8fed225469682b248eb03297590be4d13c56f999b7aee60462c20518672995783a9b0a7dba1837d0ea1b65575a6384405b247f595886cc9aef07148631a816c4b5a8b0ea44ac7ea69bc374761f3f0eec10e580eaaf4c0df51ddacb2806115657b3a77ddbf2bc74fd7f8f5105f997b0573e91d68a4646852ea4eeca4f7d757e6ddf55d342dc1bc7227e296181ebcc10f3c2d88126e309005b6a51909f7d9568f5ec6ff7deca98eeec65d50189bb88594cb5c75c6a3ec3efa9e1e4defe462416b4d437ee0fafe45ea60cded842362828e07a18cc468e14ce01326266998d8d42088687fe63e7b4e1cf9b36d4b12a384234f09a31257003e2c9cde011e86eec4648b6a70812cb95dd5e48398c548605e1c6922e1e07182c10c2237b3514ba8a64e7f544832d5ecc12f322ed6acd4b7673631751a6083ddac83b6f158d1a898eaf49edc5415c398754fef3d9ac37dca801fdf703eac52d4dcb69b8c75627f097bc8f4ede761e4fd5f31661e3ef973020a0150ddeeb8893f1a4b207144deeb0f7fd2ca5be0477c0a9c511bd18c6c99581e525d8a67ab9c794dea118218d0ca84270de05ca765aa6cd5d7579cda0ce36a2dc994d4fe368ce2f445c54269647be5b0aaffab816a9ba9c88fae8a5450b5734eb9460f581e0bc74971a064e58822c578aefc0188d4a152a16e6e668f8fb"
            + "4810898e5b41b7742ae18bedd32231b1");
    textlist.add(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
            + "1ae10b594f09e26a7e902ecbd0600691");
    textlist.add(
        "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b"
            + "eead9d67890cbb22392336fea1851f38");

    ArrayList<String> keyList = new ArrayList<>();
    keyList.add("54ee7693c01bc4757700f17b37cb2df34d76e8e351ccff60e2328ed8aab5f2b1");
    keyList.add("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    keyList.add("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");

    ArrayList<byte[]> noncList = new ArrayList<>();
    noncList.add(new byte[12]);
    noncList.add(ByteArray.fromHexString("070000004041424344454647"));
    noncList.add(ByteArray.fromHexString("000000000102030405060708"));

   ArrayList<byte[]> aadList = new ArrayList<>();
    aadList.add(null);
    aadList.add(ByteArray.fromHexString("50515253c0c1c2c3c4c5c6c7"));
    aadList.add(ByteArray.fromHexString("f33388860000000000004e91"));

    for (int i = 1; i < textlist.size(); i++){
      String text = textlist.get(i);
      byte[] key = ByteArray.fromHexString(keyList.get(i));
      byte[] aad = aadList.get(i);
      byte[] none = noncList.get(i);
      byte[] cipher = ByteArray.fromHexString(text);
      byte[] plain = new byte[cipher.length];
      chacha20poly1305_crypt(aad, key, none, plain, cipher, 0);
      System.out.println(ByteArray.toHexString(plain));
    }
  }
}
