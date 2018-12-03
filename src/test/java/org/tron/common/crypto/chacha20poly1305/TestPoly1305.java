package org.tron.common.crypto.chacha20poly1305;

import java.util.Arrays;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.utils.ByteArray;

// compare against Bouncy Castle's implementation

/*
 * Test cases for standalone implementation of ChaCha 256-bit
 * <p/>
 * Created by Clarence Ho on 20150729
 */
public class TestPoly1305 {

  private class TestClass {

    public byte[] input;
    public byte[] key;
    public byte[] tag;
  }

  @Test

  public void poly1305_test() {
    TestClass c1 = new TestClass();
    c1.input = ByteArray.fromHexString("48656c6c6f20776f726c6421");
    c1.key = ByteArray
        .fromHexString("746869732069732033322d62797465206b657920666f7220506f6c7931333035");
    c1.tag = ByteArray.fromHexString("a6f745008f81c916a20dcc74eef2b2f0");

    byte[] out = Poly1305.poly1305_auth(c1.input,c1.input.length, c1.key);
    Assert.assertTrue(Arrays.equals(out, c1.tag));
  }


}
