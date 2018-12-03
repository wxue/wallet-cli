package org.tron.common.crypto.digital;

import org.apache.commons.lang3.ArrayUtils;
import org.tron.common.utils.ByteArray;

public class UnsignedShort implements UnsignedNumber {

  //Big endian
  private byte[] values;

  public UnsignedShort(byte[] bytes) {
    values = new byte[2];
    if (ArrayUtils.isEmpty(bytes)) {
      values[0] = values[1] = 0;
      return;
    }
    if (bytes.length == 1) {
      values[0] = 0;
      values[1] = bytes[0];
      return;
    }
    values[0] = bytes[0];
    values[1] = bytes[1];
  }

  public UnsignedShort(long value) {
    values = new byte[2];
    values[0] = (byte) ((value & 0xFF00) >> 8);
    values[1] = (byte) (value & 0x00FF);
  }

  public UnsignedShort leftShift(int n) {
    if (n >= 16 || n < 0) {
      return new UnsignedShort(0);
    }

    byte[] values = new byte[2];
    values[0] = this.values[0];
    values[1] = this.values[1];

    if (n >= 8) {
      values[0] = values[1];
      values[1] = 0;
      n -= 8;
    }
    if (n != 0) {
      byte a = (byte) (values[0] << n);
      byte b = (byte) (values[1] << n);
      byte c = (byte) ((values[1] & 0xFF) >> (8 - n));
      values[0] = (byte) (a | c);
      values[1] = b;
    }
    return new UnsignedShort(values);
  }

  public UnsignedShort rightShift(int n) {
    if (n >= 16 || n < 0) {
      return new UnsignedShort(0);
    }

    byte[] values = new byte[2];
    values[0] = this.values[0];
    values[1] = this.values[1];

    if (n >= 8) {
      values[1] = values[0];
      values[0] = 0;
      n -= 8;
    }
    if (n != 0) {
      byte a = (byte) ((values[0] & 0xFF) >> n);
      byte b = (byte) (values[0] << (8 - n));
      byte c = (byte) ((values[1] & 0xFF) >> n);
      values[0] = a;
      values[1] = (byte) (b | c);
    }
    return new UnsignedShort(values);
  }

  public UnsignedShort AND(UnsignedShort another) {
    byte[] values = new byte[2];
    values[0] = (byte) (this.values[0] & another.values[0]);
    values[1] = (byte) (this.values[1] & another.values[1]);
    return new UnsignedShort(values);
  }

  public UnsignedShort AND(long another) {
    UnsignedShort a = new UnsignedShort(another);
    return this.AND(a);
  }

  public UnsignedShort OR(UnsignedShort another) {
    byte[] values = new byte[2];
    values[0] = (byte) (this.values[0] | another.values[0]);
    values[1] = (byte) (this.values[1] | another.values[1]);
    return new UnsignedShort(values);
  }

  public UnsignedShort OR(long another) {
    UnsignedShort a = new UnsignedShort(another);
    return this.OR(a);
  }

  public UnsignedShort ADD(UnsignedShort another) {
    long r = this.toLong() + another.toLong();
    return new UnsignedShort(r);
  }

  public UnsignedShort ADD(long another) {
    long r = this.toLong() + another;
    return new UnsignedShort(r);
  }

  public UnsignedShort NON() {
    byte[] values = new byte[2];
    values[0] = (byte) (255 - this.values[0]);
    values[1] = (byte) (255 - this.values[1]);
    return new UnsignedShort(values);
  }

  public UnsignedShort SUB(UnsignedShort another) {
    long r = this.toLong() - another.toLong();
    return new UnsignedShort(r);
  }

  public UnsignedShort SUB(long another) {
    long r = this.toLong() - another;
    return new UnsignedShort(r);
  }

  public byte[] toByteArray() {
    return ArrayUtils.clone(values);
  }

  public long toLong() {
    return ((((int) values[0]) & 0xFF) << 8) + (((int) values[1]) & 0xFF);
  }

  public static void main(String[] args) {
    UnsignedShort a = new UnsignedShort(0xEDED);
    a =a.NON();
    System.out.println(a.toLong());
    System.out.println(ByteArray.toHexString(a.toByteArray()));
    a.rightShift(1);
    System.out.println(ByteArray.toHexString(a.toByteArray()));
  }
}
