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

//    SecureRandom random = new SecureRandom();
//    syncExecutor.scheduleWithFixedDelay(() -> {

    String[] aList = new String[] {
        "\"TATCuhKichpkhFqGTRGunnfFAMZbheHmHi\"",
        "\"TAUAkVWJwLrzrgbRAB1dfHGAUKYqj2reYG\"",
        "\"TBT9Df7BLD3YHzrM8wrFjvNmk2wqg1SUiE\"",
        "\"TCFgVLBYZzfxonRjCz7u5oTG1PR4EAkk1E\"",
        "\"TCjgqPqcDmBXAGrS5VhPVaY9GoZtRFSTuF\"",
        "\"TCjgqPqcDmBXAGrS5VhPVaY9GoZtRFSTuF\"",
        "\"TCq1whf1K4ApYSaHvw1u6dyJww4YndrV7C\"",
        "\"TD92pYApwVJQGWuoiwLDPAPRtYXekwM89b\"",
        "\"TDaJj2FD6ZMuobxXWSY5FfwUnKpnizPR8S\"",
        "\"TE3bfxzX9oBuzeUPyiMxwwdsBDcMneh7Su\"",
        "\"TEr4rZUVBNLmqXWASGm9gNUwgoAxwhCgAg\"",
        "\"TEr4rZUVBNLmqXWASGm9gNUwgoAxwhCgAg\"",
        "\"TEtJ5UZHZN7mZB693Pcm2kHBywpuLvcKXR\"",
        "\"TFR46eP1w68ETJzx9My7yEWGYdSRxbqZqx\"",
        "\"TGKGnaYqMJK7tZvcfspjViRFVtG7p2hnRH\"",
        "\"TGKGnaYqMJK7tZvcfspjViRFVtG7p2hnRH\"",
        "\"TGKGnaYqMJK7tZvcfspjViRFVtG7p2hnRH\"",
        "\"TGzggSthWj3Mx76bGDose347g1sSj11qrL\"",
        "\"TGzggSthWj3Mx76bGDose347g1sSj11qrL\"",
        "\"THtKJrcAPrpTHcA8EETY5gwE3377oXWwBs\"",
        "\"TJf1s5sWVuTyJzQ468kGbD2NXB4ijpgKsc\"",
        "\"TJMYGCEyEJoWv8qV5waGMG1598ayPd1mZL\"",
        "\"TJXuwBAh2uhqvKmHrFX8njaKKXMGdWn3CS\"",
        "\"TKaEZyHPqQ7vUPakB3Es8TRgME585J5tqM\"",
        "\"TKQY4SrpQt6JaSuU3GzRKb2CmLfvJSr3yG\"",
        "\"TKX9WKYgYuoSYB3TRiCKn3h3ZWxx1eaP7L\"",
        "\"TL1XWdJCYsu5xrVDQcVgCnF5DkBTgFvsUK\"",
        "\"TLaH3BxpL9hafvRNMNn8y6wip8u8gPcWJ6\"",
        "\"TLDoDRmcF6quYFMBP4virB9c82XYg367YG\"",
        "\"TLUXwauduPr1iBkzSh2X9nSEA7eMoDz32A\"",
        "\"TLUZNn3XTionssBDq44wnUSf9xmbsn4g6u\"",
        "\"TM3ozXKAkT2SQWSsh7cTdtBHqVmBYE6bXS\"",
        "\"TMXNZ2JaceWnUYETsZThdNULWKzs3rwUwa\"",
        "\"TN8p9sUqKgdnvWqbE4dCq6bTV6GhkpZhXP\"",
        "\"TPPD8FicRobj3M5jonEgXfCAESfDuPuFry\"",
        "\"TQ6jBwim3LquFbbxnivdRNyWFGLpYwhwRB\"",
        "\"TQAg2T2vJcHAX9sbKTEoaoWzt512yUjiFD\"",
        "\"TSNHwRSAudFatEocUoi5PvdLouwGn6F7gD\"",
        "\"TSNHwRSAudFatEocUoi5PvdLouwGn6F7gD\"",
        "\"TTo6Z5Uxwc86WvcARXuHpJN6ppXxn8xnCp\"",
        "\"TU5xq9SMWZAWwUanhoeh5zMbJ4eeC4oUtD\"",
        "\"TUGU7ZFN731c8WM4nXo4VvGmD5SwsCHJPd\"",
        "\"TUGU7ZFN731c8WM4nXo4VvGmD5SwsCHJPd\"",
        "\"TUHXGqq4o6niBgTHHp1mNzx74FYRYPgDAt\"",
        "\"TUt7JpmwKaKj2RGDKV49BkUBQxAwWwwENe\"",
        "\"TVhM5wpBwqLjX92eyeaxQL8BY43LSTZRMz\"",
        "\"TVhM5wpBwqLjX92eyeaxQL8BY43LSTZRMz\"",
        "\"TVoy1bswnj4cZakLNAs8qCdQx8PXYU8yB7\"",
        "\"TVvP6w9XHA4fHzDmQWQs5BGgDEFW9svVw1\"",
        "\"TYgF6C5c2M9iaDGwnxQHuwHZURH4BLZ4Yy\"",
        "\"TYKuG3fyo6UKZ5NRjWM2QCGwqDo3p7Y3oq\"",
        "\"TZ1jFPffTB56c3k4SZczJJQiqeAyVa3p4G\"",
        "\"TZFWrE8dku2Yk3nwAERpu7hPcVCz7Ubtu3\""
    };

    for (String targetData : aList) {
        System.out.print(targetData + " ");
        try {
          String[] parameters = new String[]{"TQLNpTDwUQfnvTojatqRSqPpmW9WwWvkem",
              "balanceOf(address)", targetData, "false", "100000000", "0"};
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
}
