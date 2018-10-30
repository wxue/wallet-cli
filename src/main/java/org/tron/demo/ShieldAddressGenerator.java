package org.tron.demo;

import java.util.Random;
import org.tron.common.crypto.Sha256Hash;
import org.tron.common.utils.ByteArray;
import org.tron.keystore.StringUtils;

public class ShieldAddressGenerator {

  public static final int LENGTH = 32; // bytes

  public byte[] generatePrivateKey() {
    return generatePrivateKey(0L);
  }

  public byte[] generatePrivateKey(long seed) {
    byte[] result = new byte[LENGTH];
    if (seed != 0L) {
      new Random(seed).nextBytes(result);
    } else {
      new Random().nextBytes(result);
    }
    Integer i = result[0] & 0x0F;
    result[0] = i.byteValue();
    return result;
  }


  private byte[] generatePublicKey(byte[] privateKey) {
    if (privateKey.length != 32) {
      throw new RuntimeException("Wrong length，expect：256，real：" + privateKey.length);
    }
    if ((privateKey[0] & 0xF0) != 0) {
      throw new RuntimeException("The first 4 digits must be 0");
    }
    return Sha256Hash.hash(privateKey);
  }

  public static void main(String[] args) {
    ShieldAddressGenerator shieldAddressGenerator = new ShieldAddressGenerator();

    byte[] privateKey = shieldAddressGenerator.generatePrivateKey(100L);
    byte[] publicKey = shieldAddressGenerator.generatePublicKey(privateKey);

    String privateKeyString = ByteArray.toHexString(privateKey);
    String publicKeyString = ByteArray.toHexString(publicKey);

    System.out.println("privateKey:" + privateKeyString);
    System.out.println("publicKey :" + publicKeyString);

  }


}
