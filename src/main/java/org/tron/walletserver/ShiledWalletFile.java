package org.tron.walletserver;

import java.util.HashMap;
import org.apache.commons.lang3.ArrayUtils;
import org.tron.common.crypto.Sha256Hash;
import org.tron.common.utils.ByteArray;
import org.tron.common.zksnark.CmUtils;
import org.tron.common.zksnark.CmUtils.CmTuple;
import org.tron.core.exception.CipherException;
import org.tron.keystore.Wallet;
import org.tron.keystore.WalletFile;

public class ShiledWalletFile {

  private WalletFile walletFile;
  private byte[] password;
  private HashMap<String, CmTuple> cmInfoMap;

  public ShiledWalletFile(WalletFile walletFile, byte[] password) throws CipherException {
    this.walletFile = walletFile;
    if (!ArrayUtils.isEmpty(password)) {
      String fileName = walletFile.getAddress() + ".cm";
      cmInfoMap = CmUtils.loadCmFile(fileName, password);
    }
    this.password = Sha256Hash.hash(password);
  }

  public WalletFile getWalletFile() {
    return walletFile;
  }

  public CmTuple getCm(String cm) {
    return cmInfoMap.get(cm);
  }

  public void saveCm(CmTuple cmTuple) throws CipherException {
    cmInfoMap.put(ByteArray.toHexString(cmTuple.getCm()), cmTuple);
    String fileName = walletFile.getAddress() + ".cm";
    CmUtils.saveCmFile(fileName, password, cmInfoMap);
  }

  public boolean useCmInfo(String cm) throws CipherException {
    CmTuple cmTuple = cmInfoMap.get(cm);
    if (cmTuple != null) {
      cmTuple.setUsed();
      cmInfoMap.put(cm, cmTuple);
      String fileName = walletFile.getAddress() + ".cm";
      CmUtils.saveCmFile(fileName, password, cmInfoMap);
      return true;
    }
    return false;
  }

  public byte[] getPrivateAddress() throws CipherException {
    return Wallet.decrypt2PrivateBytes(password, walletFile);
  }

  public byte[] getPublicAddress() {
    return WalletApi.decodeFromBase58Check(walletFile.getAddress());
  }
}
