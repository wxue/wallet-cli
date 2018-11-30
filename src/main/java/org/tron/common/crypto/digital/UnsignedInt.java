package org.tron.common.crypto.digital;

import org.apache.commons.lang3.ArrayUtils;
import org.tron.common.utils.ByteArray;

public class UnsignedInt implements UnsignedNumber {

  //Big endian
  private byte[] values;

  public UnsignedInt(byte[] bytes) {
    values = new byte[4];
    for (int i = 0; i < 4; i++) {
      values[i] = 0;
    }
    if (ArrayUtils.isEmpty(bytes)) {
      return;
    }
    if (bytes.length < 4) {
      for (int i = bytes.length - 1; i >= 0; i++) {
        values[i + 4 - bytes.length] = bytes[i];
      }
    }
    for (int i = 0; i < 4; i++) {
      values[i] = bytes[i];
    }
  }

  public UnsignedInt(long value) {
    values = new byte[4];
    values[0] = (byte) ((value & 0xFF000000) >> 24);
    values[1] = (byte) ((value & 0x00FF0000) >> 16);
    values[2] = (byte) ((value & 0x0000FF00) >> 8);
    values[3] = (byte) (value & 0x000000FF);
  }

  public UnsignedInt leftShift(int n) {
    if (n >= 32 || n < 0) {
      return new UnsignedInt(0);
    }

    byte[] values = new byte[4];
    for (int i = 0; i < 4; i++) {
      values[i] = this.values[i];
    }

    if (n >= 8) {
      int m = n / 8;
      int i = 0;
      for (; i < 4 - m; i++) {
        values[i] = values[i + m];
      }
      for (; i < 4; i++) {
        values[i] = 0;
      }
      n %= 8;
    }
    if (n != 0) {
      byte a0 = (byte) ((values[0] & 0xFF) << n);
      byte a1 = (byte) ((values[1] & 0xFF) << n);
      byte b1 = (byte) ((values[1] & 0xFF) >> (8 - n));
      byte a2 = (byte) ((values[2] & 0xFF) << n);
      byte b2 = (byte) ((values[2] & 0xFF) >> (8 - n));
      byte a3 = (byte) ((values[3] & 0xFF) << n);
      byte b3 = (byte) ((values[3] & 0xFF) >> (8 - n));
      values[0] = (byte) (a0 | b1);
      values[1] = (byte) (a1 | b2);
      values[2] = (byte) (a2 | b3);
      values[3] = a3;

    }
    return new UnsignedInt(values);
  }

  public UnsignedInt rightShift(int n) {
    if (n >= 32 || n < 0) {
      return new UnsignedInt(0);
    }

    byte[] values = new byte[4];
    for (int i = 0; i < 4; i++) {
      values[i] = this.values[i];
    }

    if (n >= 8) {
      int m = n / 8;
      int i;
      for (i = 3; i >= m; i--) {
        values[i] = values[i - m];
      }
      for (i = 0; i < m; i++) {
        values[i] = 0;
      }
      n %= 8;
    }

    if (n != 0) {
      byte a0 = (byte) ((values[0] & 0xFF) >> n);
      byte b0 = (byte) ((values[0] & 0xFF) << (8 - n));
      byte a1 = (byte) ((values[1] & 0xFF) >> n);
      byte b1 = (byte) ((values[1] & 0xFF) << (8 - n));
      byte a2 = (byte) ((values[2] & 0xFF) >> n);
      byte b2 = (byte) ((values[2] & 0xFF) << (8 - n));
      byte a3 = (byte) ((values[3] & 0xFF) >> n);
      values[0] = a0;
      values[1] = (byte) (a1 | b0);
      values[2] = (byte) (a2 | b1);
      values[3] = (byte) (a3 | b2);
    }
    return new UnsignedInt(values);
  }

  public UnsignedInt AND(UnsignedInt another) {
    byte[] values = new byte[4];
    for (int i = 0; i < 4; i++) {
      values[i] = (byte) (this.values[i] & another.values[i]);
    }
    return new UnsignedInt(values);
  }

  public UnsignedInt AND(long another) {
    UnsignedInt a = new UnsignedInt(another);
    return this.AND(a);
  }

  public UnsignedInt OR(UnsignedInt another) {
    byte[] values = new byte[4];
    for (int i = 0; i < 4; i++) {
      values[i] = (byte) (this.values[i] | another.values[i]);
    }
    return new UnsignedInt(values);
  }

  public UnsignedInt OR(long another) {
    UnsignedInt a = new UnsignedInt(another);
    return this.OR(a);
  }

  public UnsignedInt ADD(UnsignedInt another) {
    long r = this.toLong() + another.toLong();
    return new UnsignedInt(r);
  }

  public byte[] toByteArray() {
    return ArrayUtils.clone(values);
  }

  public long toLong() {
    return ((((int) values[0]) & 0xFF) << 24) + ((((int) values[1]) & 0xFF) << 16) + (
        (((int) values[2]) & 0xFF) << 8) + (((int) values[3]) & 0xFF);
  }

  public static void main(String[] args) {
    UnsignedInt a = new UnsignedInt(0xEDED);
    System.out.println(ByteArray.toHexString(a.toByteArray()));
    a.rightShift(1);
    System.out.println(ByteArray.toHexString(a.toByteArray()));
  }
}
