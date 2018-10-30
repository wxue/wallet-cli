package org.tron.common.crypto.blake2b;

import java.security.NoSuchAlgorithmException;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.blake2b.security.Blake2b256Digest;
import org.tron.common.utils.ByteArray;

public class Blake2bTest {


  @Test
  public void hell() {

    Blake2b256Digest digest = new Blake2b256Digest();

    digest.update("hello".getBytes());

    byte[] result = digest.digest();

    Assert.assertEquals(ByteArray.toHexString(result), "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf");

  }

}