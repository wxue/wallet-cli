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

  public static void chacha20poly1305Encrypt(byte[] aad, byte[] key, byte[] nonce, byte[] dest,
      byte[] src)
      throws WrongKeySizeException, WrongNonceSizeException {
    byte[] poly_key = new byte[32];
    byte[] zero = new byte[32];

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

    chaCha20 = new ChaCha20(key, nonce, 1);

    byte[] cipher = new byte[src.length];
    chaCha20.decrypt(cipher, src, src.length);

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
    System.arraycopy(cipher, 0, dest, 0, cipher.length);
    System.arraycopy(tag, 0, dest, cipher.length, tag.length);
  }

  public static boolean chacha20poly1305Decrypt(byte[] aad, byte[] key, byte[] nonce, byte[] dest,
      byte[] src)
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
      System.out.println(ByteArray.toHexString(tag));
      System.out.println(ByteArray.toHexString(tag0));
      throw new WrongPolyMac();
    }

    chaCha20 = new ChaCha20(key, nonce, 1);
    chaCha20.decrypt(dest, src, src.length - 16);
    return r;
  }

  public static void test()
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

    for (int i = 0; i < textlist.size(); i++) {
      String text = textlist.get(i);
      byte[] key = ByteArray.fromHexString(keyList.get(i));
      byte[] aad = aadList.get(i);
      byte[] none = noncList.get(i);
      byte[] cipher = ByteArray.fromHexString(text);
      byte[] plain = new byte[cipher.length - 16];
      chacha20poly1305Decrypt(aad, key, none, plain, cipher);
      System.out.println("plain :::");
      System.out.println(ByteArray.toHexString(plain));

      byte[] cipher1 = new byte[plain.length + 16];
      chacha20poly1305Encrypt(aad, key, none, cipher1, plain);
      System.out.println("cipher :::");
      System.out.println(ByteArray.toHexString(cipher1));
    }
  }

  public static void test1() throws WrongKeySizeException, WrongNonceSizeException {
    String cipher =
        "15C173DA2B6B53EA9C6CAF613B542802524AB54A237938E30898F5F6D7763F926C90543D603127D3AF583F082D316BAB26CBE9B633BCB00C5C3230E718F2ECA8D7285F870ECDFED2F2D47353F8BA2B207E7BFE14FA5C60656E714BFCA8517FA36DAF2F20E9DC858E94F74375A438648A29009993C7C6F4FF7032A551E5D21702AD20382CB77F0525E687A7BA14AC7267438366DC3BB59B7059F419425FE060D90EB5D009F21B69F4C6A51D19CD593982C94E234166AB74EE15807937FE3951ADAFE8FC7F07AE16581AA59CA07DAFEB7B944B6E705FB796B74120966D9AADCDD8DBE3C7B62923A320AAEB9D85B9A2F781D39466F45BC35BEF0D0640B54AED5589C32B95EFA81ECB570A4A9200BA19304F7263A93F75CB3C6E93BB653468343DAB53C30EC7C855DF979AC84CFC79ACCBBA23D51C698ACF1A9ACF78E903DB92E874DBC77884E29C92597116A1A9C7B88B9CA81DFBB13007D0E6F0C96A470AC502113F03F5D4A7EADCE3C832E2884D59F59B550633CC96F6B5B57C9DC3314C98FBDB5EC16117EE8C2F367CA5D92666A40635C7F376F057F7EAC3E5CE038338E7DEDAC53A724AD6285E0F6DFC91527DAACDBE04DA67B22C482F667E9058A721945C7621F23805F0DA6675448146F6DF431F11339D49B16B4C9DC4AC4431D518570657F1CB47561391EF0AA2A3765232C45ED98A4F96B66EB6F9D818B1082DF5E1589FFEB4ED031C06443411B6E3E0EA49E48A411B703718F0D73A2829E486A8707332798BD987EFCA10D08D7EA0622DC66C1EF9A00467CD930AF749EFEEC77CDDCFA4C02511D3CF32D4DFCE"
            + "244B3EED98587DE54059D4EDD29C0CD6";
    //15c173da2b6b53ea9c6caf613b542802524ab54a237938e30898f5f6d7763f926c90543d603127d3af583f082d316bab26cbe9b633bcb00c5c3230e718f2eca8d7285f870ecdfed2f2d47353f8ba2b207e7bfe14fa5c60656e714bfca8517fa36daf2f20e9dc858e94f74375a438648a29009993c7c6f4ff7032a551e5d21702ad20382cb77f0525e687a7ba14ac7267438366dc3bb59b7059f419425fe060d90eb5d009f21b69f4c6a51d19cd593982c94e234166ab74ee15807937fe3951adafe8fc7f07ae16581aa59ca07dafeb7b944b6e705fb796b74120966d9aadcdd8dbe3c7b62923a320aaeb9d85b9a2f781d39466f45bc35bef0d0640b54aed5589c32b95efa81ecb570a4a9200ba19304f7263a93f75cb3c6e93bb653468343dab53c30ec7c855df979ac84cfc79accbba23d51c698acf1a9acf78e903db92e874dbc77884e29c92597116a1a9c7b88b9ca81dfbb13007d0e6f0c96a470ac502113f03f5d4a7eadce3c832e2884d59f59b550633cc96f6b5b57c9dc3314c98fbdb5ec16117ee8c2f367ca5d92666a40635c7f376f057f7eac3e5ce038338e7dedac53a724ad6285e0f6dfc91527daacdbe04da67b22c482f667e9058a721945c7621f23805f0da6675448146f6df431f11339d49b16b4c9dc4ac4431d518570657f1cb47561391ef0aa2a3765232c45ed98a4f96b66eb6f9d818b1082df5e1589ffeb4ed031c06443411b6e3e0ea49e48a411b703718f0d73a2829e486a8707332798bd987efca10d08d7ea0622dc66c1ef9a00467cd930af749efeec77cddcfa4c02511d3cf32d4dfce
    //    bc48ab0987ebfcdb145dc73ca37e46cf
    String plain = "00000000000000000000960CE599B807F5E094A0CF8FD9F69449F96DEF81E4B178A63593C5477C485084EB5DB9A85F56A8CC7402D550F426F4915D81038E366A008882CCB1B0B879004F75742032000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    String K = "4ED8FB7A6AC243084A5BDAD12A891F1E40E802E478853B1FA4D87F7E98452DE2";
    String nonce = "000000000000000000000000";

    byte[] result = new byte[601];
    chacha20poly1305Encrypt(null, ByteArray.fromHexString(K), ByteArray.fromHexString(nonce),
        result, ByteArray.fromHexString(plain));
    System.out.println(
        ByteArray.toHexString(Arrays.copyOfRange(result, result.length - 16, result.length)));
  }

  public static void main(String[] args)
      throws WrongNonceSizeException, WrongPolyMac, WrongKeySizeException {
    test();
  }
}
