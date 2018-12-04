package org.tron.common.zksnark;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Utils;
import org.tron.core.exception.CipherException;
import org.tron.keystore.Wallet;

public class CmUtils {

  public static HashMap<String, CmTuple> loadCmFile(String fileName, byte[] password)
      throws CipherException, IOException {

    HashMap<String, CmTuple> cmInfoMap = new HashMap<>();
    BufferedReader file = null;
    try {
      FileReader fileReader = new FileReader(fileName);
      if (fileReader == null) {
        System.out.printf("%s is not exits!\n", fileName);
        return cmInfoMap;
      }
      file = new BufferedReader(fileReader);
      String line;
      while ((line = file.readLine()) != null) {
        byte[] cipher = ByteArray.fromHexString(line);
        byte[] plain = Wallet.commonDec(password, cipher);
        CmTuple cmTuple = CmTuple.parseFromBytes(plain);
        cmInfoMap.put(cmTuple.getKeyString(), cmTuple);
      }
    } catch (FileNotFoundException e) {
      System.out.printf("%s is not exits!\n", fileName);
      return cmInfoMap;
    } catch (IOException e) {
      throw e;
    } finally {
      if (file != null) {
        file.close();
      }
    }
    return cmInfoMap;
  }

  public static void saveCmFile(String fileName, byte[] password,
      HashMap<String, CmTuple> cmInfoMap) throws CipherException {
    BufferedWriter bufWriter = null;
    try {
      bufWriter = new BufferedWriter(new FileWriter(fileName));

      for (CmTuple cmTuple : cmInfoMap.values()) {
        try {
          byte[] plain = cmTuple.toByteArray();
          byte[] cipher = Wallet.commonEnc(password, plain);
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

  public static class CmTuple implements Serializable {

    private static int numCases;
    private int caseNum;
    private byte[] cm;
    private byte[] addr_pk;
    private byte[] addr_sk;
    private byte[] v;
    private byte[] rho;
    private byte[] r;
    private byte[] txId;
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
      txId = Utils.hexToBytes(x[7]);
      index = Integer.parseInt(x[8]);
    }

    public CmTuple(byte[] cm, byte[] addr_pk, byte[] addr_sk, byte[] v, byte[] rho, byte[] r,
        int index, byte[] txId) {
      this.cm = cm;
      this.addr_pk = addr_pk;
      this.addr_sk = addr_sk;
      this.v = v;
      this.rho = rho;
      this.r = r;
      this.used = 0x00;
      this.index = index;
      this.txId = txId;
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
      line.append(ByteArray.toHexString(txId));
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

    public byte[] getTxId() {
      return txId;
    }

    public int getIndex() {
      return index;
    }

    public byte getUsed() {
      return used;
    }

    public void setUsed() {
      this.used = 0x01;
    }
  }
}
