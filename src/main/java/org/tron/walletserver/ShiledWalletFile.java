package org.tron.walletserver;

import java.io.IOException;
import java.util.HashMap;
import org.apache.commons.lang3.ArrayUtils;
import org.tron.common.utils.ByteArray;
import org.tron.common.zksnark.CmUtils;
import org.tron.common.zksnark.CmUtils.CmTuple;
import org.tron.core.exception.CipherException;
import org.tron.keystore.Wallet;
import org.tron.keystore.WalletFile;

public class ShiledWalletFile {

  private static final String FilePath_Shiled = "./WalletShiled/";
  private WalletFile walletFile;
  private byte[] password;
  private HashMap<String, CmTuple> cmInfoMap;

  public ShiledWalletFile(WalletFile walletFile, byte[] password)
      throws CipherException, IOException {
    if (!Wallet.validPassword(password, walletFile)) {
      return;
    }
    this.walletFile = walletFile;
    if (!ArrayUtils.isEmpty(password)) {
      String fileName = walletFile.getAddress() + ".cm";
      byte[] key = Wallet.getDerivedKey(password, walletFile);
      cmInfoMap = CmUtils.loadCmFile(FilePath_Shiled + fileName, key);
    }
    this.password = ArrayUtils.clone(password);
  }

  public WalletFile getWalletFile() {
    return walletFile;
  }

  public CmTuple getCm(String cm) {
    return cmInfoMap.get(cm);
  }

  public boolean hashCm(String cm){
    return cmInfoMap.containsKey(cm);
  }

  public void listCoin() {
    for (String cm : cmInfoMap.keySet()) {
      CmTuple cmTuple = cmInfoMap.get(cm);
      System.out.printf("CM : %s , balance : %d, %s\n", cm, ByteArray.toLong(cmTuple.getV()),
          cmTuple.getUsed() == 0x01 ? "is used" : "is not used");
    }
  }

  public void saveCm(CmTuple cmTuple) throws CipherException {
    cmInfoMap.put(ByteArray.toHexString(cmTuple.getCm()), cmTuple);
    String fileName = walletFile.getAddress() + ".cm";
    byte[] key = Wallet.getDerivedKey(password, walletFile);
    CmUtils.saveCmFile(FilePath_Shiled + fileName, key, cmInfoMap);
  }

  public boolean useCmInfo(String cm) throws CipherException {
    CmTuple cmTuple = cmInfoMap.get(cm);
    if (cmTuple != null) {
      cmTuple.setUsed();
      cmInfoMap.put(cm, cmTuple);
      String fileName = walletFile.getAddress() + ".cm";
      byte[] key = Wallet.getDerivedKey(password, walletFile);
      CmUtils.saveCmFile(FilePath_Shiled + fileName, key, cmInfoMap);
      return true;
    }
    return false;
  }

  public byte[] getPrivateAddress() throws CipherException {
    return Wallet.decrypt2PrivateBytes(password, walletFile);
  }

  public byte[] getPublicAddress() {
    return WalletApi.decodeBase58Check(walletFile.getAddress());
  }
}
