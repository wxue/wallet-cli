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
        "\"TJMYGCEyEJoWv8qV5waGMG1598ayPd1mZL\"",
        "\"TJMYGCEyEJoWv8qV5waGMG1598ayPd1mZL\"",
        "\"TKaEZyHPqQ7vUPakB3Es8TRgME585J5tqM\"",
        "\"TVoy1bswnj4cZakLNAs8qCdQx8PXYU8yB7\"",
        "\"TQ6jBwim3LquFbbxnivdRNyWFGLpYwhwRB\"",
        "\"TUGU7ZFN731c8WM4nXo4VvGmD5SwsCHJPd\"",
        "\"TVhM5wpBwqLjX92eyeaxQL8BY43LSTZRMz\"",
        "\"TD92pYApwVJQGWuoiwLDPAPRtYXekwM89b\"",
        "\"TGKGnaYqMJK7tZvcfspjViRFVtG7p2hnRH\"",
        "\"TGKGnaYqMJK7tZvcfspjViRFVtG7p2hnRH\"",
        "\"TGKGnaYqMJK7tZvcfspjViRFVtG7p2hnRH\"",
        "\"TEr4rZUVBNLmqXWASGm9gNUwgoAxwhCgAg\"",
        "\"TTo6Z5Uxwc86WvcARXuHpJN6ppXxn8xnCp\"",
        "\"TLaH3BxpL9hafvRNMNn8y6wip8u8gPcWJ6\"",
        "\"TGzggSthWj3Mx76bGDose347g1sSj11qrL\"",
        "\"TYgF6C5c2M9iaDGwnxQHuwHZURH4BLZ4Yy\"",
        "\"TCq1whf1K4ApYSaHvw1u6dyJww4YndrV7C\"",
        "\"TLDoDRmcF6quYFMBP4virB9c82XYg367YG\"",
        "\"TEr4rZUVBNLmqXWASGm9gNUwgoAxwhCgAg\"",
        "\"TQAg2T2vJcHAX9sbKTEoaoWzt512yUjiFD\"",
        "\"TKX9WKYgYuoSYB3TRiCKn3h3ZWxx1eaP7L\"",
        "\"TUt7JpmwKaKj2RGDKV49BkUBQxAwWwwENe\"",
        "\"TLUXwauduPr1iBkzSh2X9nSEA7eMoDz32A\"",
        "\"TUGU7ZFN731c8WM4nXo4VvGmD5SwsCHJPd\"",
        "\"TAUAkVWJwLrzrgbRAB1dfHGAUKYqj2reYG\"",
        "\"TATCuhKichpkhFqGTRGunnfFAMZbheHmHi\"",
        "\"TVvP6w9XHA4fHzDmQWQs5BGgDEFW9svVw1\"",
        "\"TSNHwRSAudFatEocUoi5PvdLouwGn6F7gD\"",
        "\"TBT9Df7BLD3YHzrM8wrFjvNmk2wqg1SUiE\"",
        "\"TSNHwRSAudFatEocUoi5PvdLouwGn6F7gD\"",
        "\"TYKuG3fyo6UKZ5NRjWM2QCGwqDo3p7Y3oq\"",
        "\"TDaJj2FD6ZMuobxXWSY5FfwUnKpnizPR8S\"",
        "\"TJXuwBAh2uhqvKmHrFX8njaKKXMGdWn3CS\"",
        "\"TGzggSthWj3Mx76bGDose347g1sSj11qrL\"",
        "\"TMXNZ2JaceWnUYETsZThdNULWKzs3rwUwa\"",
        "\"TEtJ5UZHZN7mZB693Pcm2kHBywpuLvcKXR\"",
        "\"TZ1jFPffTB56c3k4SZczJJQiqeAyVa3p4G\"",
        "\"TZFWrE8dku2Yk3nwAERpu7hPcVCz7Ubtu3\"",
        "\"TUHXGqq4o6niBgTHHp1mNzx74FYRYPgDAt\"",
        "\"TL1XWdJCYsu5xrVDQcVgCnF5DkBTgFvsUK\"",
        "\"TPPD8FicRobj3M5jonEgXfCAESfDuPuFry\"",
        "\"TKQY4SrpQt6JaSuU3GzRKb2CmLfvJSr3yG\"",
        "\"TCjgqPqcDmBXAGrS5VhPVaY9GoZtRFSTuF\"",
        "\"TM3ozXKAkT2SQWSsh7cTdtBHqVmBYE6bXS\"",
        "\"TCjgqPqcDmBXAGrS5VhPVaY9GoZtRFSTuF\"",
        "\"TFR46eP1w68ETJzx9My7yEWGYdSRxbqZqx\"",
        "\"TN8p9sUqKgdnvWqbE4dCq6bTV6GhkpZhXP\"",
        "\"THtKJrcAPrpTHcA8EETY5gwE3377oXWwBs\"",
        "\"TE3bfxzX9oBuzeUPyiMxwwdsBDcMneh7Su\"",
        "\"TLUZNn3XTionssBDq44wnUSf9xmbsn4g6u\"",
        "\"TU5xq9SMWZAWwUanhoeh5zMbJ4eeC4oUtD\"",
        "\"TVhM5wpBwqLjX92eyeaxQL8BY43LSTZRMz\"",
        "\"TCFgVLBYZzfxonRjCz7u5oTG1PR4EAkk1E\"",
        "\"TJf1s5sWVuTyJzQ468kGbD2NXB4ijpgKsc\"",
        "\"TCjgqPqcDmBXAGrS5VhPVaY9GoZtRFSTuF\"",
        "\"TCjgqPqcDmBXAGrS5VhPVaY9GoZtRFSTuF\"",
        "\"TAziRkQbbGnZNg22qgb2SvQscTHLSemsJV\"",
        "\"TP7XndPnTeN2jnxrfX9yKmJ3zpmQ4HzM1b\"",
        "\"TCfGSJ488jHjCSXebgEHgQUZwwTf5LHANj\"",
        "\"TVhM5wpBwqLjX92eyeaxQL8BY43LSTZRMz\"",
        "\"TDS2WHWc24zUxwBf8wu5wqND7Q8ci6J76Y\"",
        "\"TQGdWDRTSWEFru2MbLUmUVnPKpi7w2UZCe\"",
        "\"TYxqKAT2Ejm5vpp2e6anmaqkdbhaohAker\"",
        "\"TKQY4SrpQt6JaSuU3GzRKb2CmLfvJSr3yG\"",
        "\"TPmaFNUnhNbt6HraNf8uJhoL31L1nTkHLd\"",
        "\"TAoJK3gtCN5HttMtbjA56jFiVt5LCLGwh6\"",
        "\"THKxPjBKpVePZfduD1Nr5YF2E4oaWBV7ec\"",
        "\"TKX9WKYgYuoSYB3TRiCKn3h3ZWxx1eaP7L\"",
        "\"TA7tpeM3Jy5guA4mK2JRgKfTjxDZo5rJ3r\"",
        "\"TYDf7HaDAfUHi2H4WWAaR9K76XncCbAK3m\"",
        "\"TMNjjiQACNbuxZRWv2tkLVMekxDgbPBDNi\"",
        "\"TH3HPw2ih8AmGk4EYpmS5WX9eGzFCoPCap\"",
        "\"TWYEhejKfLu9Wq2CvnWrJToaWUvJf2Tksy\"",
        "\"TBnByNDEGyi1o7wpHb5j1zjrXocKmN4hJp\"",
        "\"TQMwh1NFfb8XXtP52fDiGsiVsc77iFMyRv\"",
        "\"TGpe6J9WmYiY6k9HbdM9baNUzTkwampmUU\""
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