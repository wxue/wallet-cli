package org.tron.common.utils;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.tron.demo.ZksnarkTransferDemo;

public class CmUtils {

  static private String CM_FILE_NAME = "cmInfoFile.data";
  static public HashMap<byte[], CmTuple> cmInfoMap = loadCmFile(CM_FILE_NAME);

  public static HashMap<byte[], CmTuple> loadCmFile(String fileName) {

    HashMap<byte[], CmTuple> cmInfoMap = new HashMap<>();
    BufferedReader file = null;
    try {
      InputStream is = ZksnarkTransferDemo.class.getResourceAsStream(fileName);
      if (is == null) {
        throw new IOException("Resource not found: " + fileName);
      }
      file = new BufferedReader(new InputStreamReader(is));
      String line;
      while ((line = file.readLine()) != null) {
        CmTuple cmTuple = new CmTuple(line);
        cmInfoMap.put(cmTuple.cm, cmTuple);
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

  public static void saveCmFile(String fileName) {
    FileWriter file = null;
    try {
      file = new FileWriter(fileName);
      BufferedWriter bufWriter = new BufferedWriter(file);

      cmInfoMap.values().forEach(cmTuple -> {
            try {
              bufWriter.write(cmTuple.toLine());
            } catch (IOException e) {
              e.printStackTrace();
            }
          }
      );

    } catch (
        IOException e) {
      e.printStackTrace();
    } finally {
      if (file != null) {
        try {
          file.close();
        } catch (IOException e) {
        }
      }
    }


  }

  public static void addCmInfo(byte[] cm, byte[] addr_pk, byte[] v, byte[] rho, byte[] r,
      byte[] s) {
    CmTuple cmTuple = new CmTuple(cm, addr_pk, v, rho, r, s);
    cmInfoMap.put(cmTuple.cm, cmTuple);
  }

  public static void useCmInfo(byte[] cm) {
    CmTuple cmTuple = cmInfoMap.get(cm);
    cmTuple.used = 0x01;
    cmInfoMap.put(cm, cmTuple);
  }


  public static CmTuple getCm(byte[] cm) {
    return cmInfoMap.get(cm);
  }


  public static class CmTuple {

    public static int numCases;
    public int caseNum;
    public byte[] cm;
    public byte[] addr_pk;
    public byte[] v;
    public byte[] rho;
    public byte[] r;
    public byte[] s;
    public byte used;

    public CmTuple(String line) {
      caseNum = ++numCases;
      String[] x = line.split(":");
      cm = Utils.hexToBytes(x[0]);
      addr_pk = Utils.hexToBytes(x[1]);
      v = Utils.hexToBytes(x[2]);
      rho = Utils.hexToBytes(x[3]);
      r = Utils.hexToBytes(x[4]);
      s = Utils.hexToBytes(x[5]);
      used = Utils.hexToBytes(x[7])[0];
    }

    public CmTuple(byte[] cm, byte[] addr_pk, byte[] v, byte[] rho, byte[] r,
        byte[] s) {
      this.cm = cm;
      this.addr_pk = addr_pk;
      this.v = v;
      this.rho = rho;
      this.r = r;
      this.s = s;
      used = 0x00;
    }

    public String toLine() {
      StringBuilder line = new StringBuilder();
      line.append(ByteArray.toHexString(cm));
      line.append(ByteArray.toHexString(addr_pk));
      line.append(ByteArray.toHexString(v));
      line.append(ByteArray.toHexString(rho));
      line.append(ByteArray.toHexString(r));
      line.append(ByteArray.toHexString(s));
      line.append((char) used);
      return line.toString();
    }

  }

  public static void main(String[] args) {
    //test load/save/add/use
  }


}
