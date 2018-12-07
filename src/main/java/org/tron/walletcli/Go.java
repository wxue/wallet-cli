package org.tron.walletcli;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.util.encoders.Hex;
import org.tron.common.utils.AbiUtil;
import org.tron.core.exception.CancelException;
import org.tron.core.exception.CipherException;
import org.tron.core.exception.EncodingException;
import org.tron.protos.Protocol.Account;
import org.tron.walletcli.WalletApiWrapper;
import org.tron.walletserver.WalletApi;

public class Go {


  private static ScheduledExecutorService syncExecutor = Executors
      .newSingleThreadScheduledExecutor();

  private static WalletApiWrapper walletApiWrapper = new WalletApiWrapper();

  public static void main(String[] args) throws IOException, CipherException {
    walletApiWrapper.login("Aa113113".toCharArray());

    for (int i = 0; i <= 544408; i++) {

        System.out.print(i + " ");
        try {
          String[] parameters = new String[]{"TP82MkFYwLXzM5WowhJ4FfMHSP8RPzrhSC",
              "check(uint256)", String.valueOf(i), "false", "100000000", "0"};
          triggerContract(parameters);
        } catch (Throwable t) {
          System.out.println("triggerContract " + t.getMessage());
        }
        // walletApiWrapper.sendCoin();
//    }, 2000, 10000, TimeUnit.MILLISECONDS);

    }

  }

  private static void triggerContract(String[] parameters)
      throws IOException, CipherException, CancelException, EncodingException {
    if (parameters == null ||
        parameters.length < 6) {
      System.out.println("TriggerContract needs 6 parameters like following: ");
      System.out.println(
          "TriggerContract contractAddress method args isHex fee_limit value");
      return;
    }

    String contractAddrStr = parameters[0];
    String methodStr = parameters[1];
    String argsStr = parameters[2];
    boolean isHex = Boolean.valueOf(parameters[3]);
    long feeLimit = Long.valueOf(parameters[4]);
    long callValue = Long.valueOf(parameters[5]);
    if (argsStr.equalsIgnoreCase("#")) {
      argsStr = "";
    }
    byte[] input = Hex.decode(AbiUtil.parseMethod(methodStr, argsStr, isHex));
    byte[] contractAddress = WalletApi.decodeFromBase58Check(contractAddrStr);

    boolean result = walletApiWrapper.callContract(contractAddress, callValue, input, feeLimit, 0, "");
    if (result) {
      //System.out.println("Broadcast the triggerContract successfully. Please check the given transaction id to get the result on blockchain using getTransactionInfoById command");
    } else {
      System.out.println("Broadcast the triggerContract failed");
    }
  }

  private void sendCoin(String[] parameters) throws IOException, CipherException, CancelException {
    if (parameters == null || parameters.length != 2) {
      System.out.println("SendCoin needs 2 parameters like following: ");
      System.out.println("SendCoin ToAddress Amount");
      return;
    }

    String toAddress = parameters[0];
    String amountStr = parameters[1];
    long amount = new Long(amountStr);

    boolean result = walletApiWrapper.sendCoin(toAddress, amount);
    if (result) {
      System.out.println("Send " + amount + " drop to " + toAddress + " successful !!");
    } else {
      System.out.println("Send " + amount + " drop to " + toAddress + " failed !!");
    }
  }

}