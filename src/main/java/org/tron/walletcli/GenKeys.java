package org.tron.walletcli;

import java.util.stream.IntStream;
import org.apache.commons.codec.binary.Hex;
import org.tron.common.crypto.ECKey;
import org.tron.common.utils.Utils;
import org.tron.walletserver.WalletClient;

public class GenKeys {

  public static void main(String args[]) {
    IntStream.range(0, 31).parallel().forEach(i -> {
      while (true) {
        ECKey eCkey = new ECKey(Utils.getRandom());
        byte[] priKey = eCkey.getPrivKeyBytes();
        byte[] addresss = eCkey.getAddress();
        String address = WalletClient.encode58Check(addresss);
        if (address.startsWith("TRX") && address.contains("SUN")) {
          System.out.println(address + " " + Hex.encodeHexString(priKey));
        }
        if (address.startsWith("TRX") && address.contains("ZION")) {
          System.out.println(address + " " + Hex.encodeHexString(priKey));
        }
      }
    });
  }

}
