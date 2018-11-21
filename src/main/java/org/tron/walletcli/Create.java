package org.tron.walletcli;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.stream.IntStream;
import org.spongycastle.util.encoders.Hex;
import org.tron.common.crypto.ECKey;
import org.tron.core.exception.CancelException;
import org.tron.core.exception.CipherException;
import org.tron.walletserver.WalletApi;

public class Create {

  public static WalletApiWrapper api = new WalletApiWrapper();

  public static void main(String[] args) throws IOException, CipherException, CancelException {
    api.login("Aa113113".toCharArray());

    Object lock = new Object();

    HashMap<String, String> address = new HashMap<>();
    IntStream.range(0,16).parallel().forEach(index -> {
      for (int i = 0; i < 400; i++) {
        ECKey ecKey = new ECKey();
        try {
          api.createAccount(WalletApi.encode58Check(ecKey.getAddress()));
        } catch (CipherException e) {
          e.printStackTrace();
        } catch (IOException e) {
          e.printStackTrace();
        } catch (CancelException e) {
          e.printStackTrace();
        }
        address.put(WalletApi.encode58Check(ecKey.getAddress()),
            Hex.toHexString(ecKey.getPrivKeyBytes()));

        System.out.println("Good " + WalletApi.encode58Check(ecKey.getAddress()) + "\t" +
            Hex.toHexString(ecKey.getPrivKeyBytes()));

        synchronized (lock) {
          String line = WalletApi.encode58Check(ecKey.getAddress()) + "\t" + Hex
              .toHexString(ecKey.getPrivKeyBytes()) + "\n";
          try {
            Files.write(Paths.get("/Users/huzhenyuan/Desktop/address.txt"), line.getBytes(),
                StandardOpenOption.APPEND);
          } catch (IOException e) {
            e.printStackTrace();
          }
        }
      }
    });

  }
}