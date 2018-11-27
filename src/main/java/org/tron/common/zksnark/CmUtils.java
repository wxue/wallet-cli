package org.tron.common.zksnark;

import com.google.protobuf.ByteString;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Utils;
import org.tron.core.exception.CipherException;
import org.tron.keystore.Wallet;

public class CmUtils {

  static private String CM_FILE_NAME = "./Wallet/cmInfoFile.data";
  static private HashMap<String, CmTuple> cmInfoMap = null;

  public static void loadCmFile(byte[] password) throws CipherException {
    cmInfoMap = loadCmFile(CM_FILE_NAME, password);
  }

  private static HashMap<String, CmTuple> loadCmFile(String fileName, byte[] password)
      throws CipherException {

    HashMap<String, CmTuple> cmInfoMap = new HashMap<>();
    BufferedReader file = null;
    try {
      FileReader fileReader = new FileReader(fileName);
      if (fileReader == null) {
        throw new IOException("Resource not found: " + fileName);
      }
      file = new BufferedReader(fileReader);
      String line;
      while ((line = file.readLine()) != null) {
        byte[] cipher = ByteArray.fromHexString(line);
        byte[] plain = Wallet.commonDec(password, cipher);
        CmTuple cmTuple = CmTuple.parseFromBytes(plain);
        cmInfoMap.put(cmTuple.getKeyString(), cmTuple);
      }
    } catch (IOException e) {
      e.printStackTrace();
    } finally {
      if (file != null) {
        try {
          file.close();
        } catch (IOException e) {
        }
      }
    }
    return cmInfoMap;
  }

  private static void saveCmFile(byte[] password) throws CipherException {
    saveCmFile(CM_FILE_NAME, password);
  }

  private static void saveCmFile(String fileName, byte[] password) throws CipherException {
    BufferedWriter bufWriter = null;
    try {
      bufWriter = new BufferedWriter(new FileWriter(fileName));

      for (CmTuple cmTuple : cmInfoMap.values()) {
        try {
          byte[] plain = cmTuple.toByteArray();
          byte[] cipher = Wallet.commonEnc(null, plain);
          bufWriter.write(ByteArray.toHexString(cipher));
          bufWriter.write("\n");
        } catch (IOException e) {
          e.printStackTrace();
        }
      }
    } catch (
        IOException e) {
      e.printStackTrace();
    } finally {
      if (bufWriter != null) {
        try {
          bufWriter.close();
        } catch (IOException e) {
        }
      }
    }
  }

  public static void addCmInfo(byte[] cm, byte[] addr_pk, byte[] addr_sk, byte[] v, byte[] rho,
      byte[] r, int index, byte[] contractId, byte[] password) throws CipherException {
    if (cmInfoMap == null) {
      loadCmFile(password);
    }
    CmTuple cmTuple = new CmTuple(cm, addr_pk, addr_sk, v, rho, r, index, contractId);
    cmInfoMap.put(cmTuple.getKeyString(), cmTuple);
  }

  public static void saveCm(CmTuple cm, byte[] password) throws CipherException {
    if (cmInfoMap == null) {
      loadCmFile(password);
    }
    cmInfoMap.put(cm.getKeyString(), cm);
    saveCmFile(password);
  }

  public static void useCmInfo(byte[] cm, byte[] password) throws CipherException {
    if (cmInfoMap == null) {
      loadCmFile(password);
    }
    CmTuple cmTuple = cmInfoMap.get(ByteArray.toHexString(cm));
    cmTuple.used = 0x01;
    cmInfoMap.put(ByteArray.toHexString(cm), cmTuple);
  }


  public static CmTuple getCm(byte[] cm, byte[] password) throws CipherException {
    if (cmInfoMap == null) {
      loadCmFile(password);
    }
    return cmInfoMap.get(ByteArray.toHexString(cm));
  }


  public static class CmTuple implements Serializable {

    private static int numCases;
    private int caseNum;
    private byte[] cm;
    private byte[] addr_pk;
    private byte[] addr_sk;
    private byte[] v;
    private byte[] rho;
    private byte[] r;
    private byte[] contractId;
    private int index;
    private byte used;

    public CmTuple(String line) {
      caseNum = ++numCases;
      String[] x = line.split(":");
      cm = Utils.hexToBytes(x[0]);
      addr_pk = Utils.hexToBytes(x[1]);
      addr_sk = Utils.hexToBytes(x[2]);
      v = Utils.hexToBytes(x[3]);
      rho = Utils.hexToBytes(x[4]);
      r = Utils.hexToBytes(x[5]);
      used = (byte) Character.digit(x[6].charAt(0), 16);
      contractId = Utils.hexToBytes(x[7]);
      index = Integer.parseInt(x[8]);
    }

    public CmTuple(byte[] cm, byte[] addr_pk, byte[] addr_sk, byte[] v, byte[] rho, byte[] r,
        int index, byte[] contractId) {
      this.cm = cm;
      this.addr_pk = addr_pk;
      this.addr_sk = addr_sk;
      this.v = v;
      this.rho = rho;
      this.r = r;
      this.used = 0x00;
      this.index = index;
      this.contractId = contractId;
    }

    public String getKeyString() {
      return ByteArray.toHexString(cm);
    }

    public String toLine() {
      StringBuilder line = new StringBuilder();
      line.append(ByteArray.toHexString(cm));
      line.append(":");
      line.append(ByteArray.toHexString(addr_pk));
      line.append(":");
      line.append(ByteArray.toHexString(addr_sk));
      line.append(":");
      line.append(ByteArray.toHexString(v));
      line.append(":");
      line.append(ByteArray.toHexString(rho));
      line.append(":");
      line.append(ByteArray.toHexString(r));
      line.append(":");
      line.append(used);
      line.append(":");
      line.append(ByteArray.toHexString(contractId));
      line.append(":");
      line.append(Integer.toString(index));
      line.append("\n");
      return line.toString();
    }

    public byte[] toByteArray() {
      return Utils.ObjectToByte(this);
    }

    public static CmTuple parseFromBytes(byte[] bytes) {
      Object object = Utils.ByteToObject(bytes);
      return (CmTuple) (object);
    }

    public int getCaseNum() {
      return caseNum;
    }

    public byte[] getCm() {
      return cm;
    }

    public byte[] getAddr_pk() {
      return addr_pk;
    }

    public byte[] getAddr_sk() {
      return addr_sk;
    }

    public byte[] getV() {
      return v;
    }

    public byte[] getRho() {
      return rho;
    }

    public byte[] getR() {
      return r;
    }

    public byte[] getContractId() {
      return contractId;
    }

    public int getIndex() {
      return index;
    }

    public byte getUsed() {
      return used;
    }
  }

  public static void main(String[] args) throws CipherException {
    //add
    byte[] cm = {0x0001};
    byte[] addr_pk = {0x02};
    byte[] addr_sk = {0x03};
    byte[] v = {0x04};
    byte[] rho = {0x05};
    byte[] r = {0x06};
    byte used = 0x00;
    byte[] contractId = {0x01, 0x02};
    int index = 11;
    CmUtils.addCmInfo(cm, addr_pk, addr_sk, v, rho, r, 11, contractId, "123456".getBytes());
    //save
    CmUtils.saveCmFile("123456".getBytes());
    //load
    CmUtils.loadCmFile("123456".getBytes());
    //get
    CmTuple cm1 = CmUtils.getCm(cm, "123456".getBytes());
    //use
    CmUtils.useCmInfo(cm, "123456".getBytes());

    byte[] bytes = cm1.toByteArray();
    byte[] cipher = Wallet.commonEnc("123456".getBytes(), bytes);
    bytes = Wallet.commonDec("123456".getBytes(), cipher);
    CmTuple cm2 = CmTuple.parseFromBytes(bytes);

  }


}
