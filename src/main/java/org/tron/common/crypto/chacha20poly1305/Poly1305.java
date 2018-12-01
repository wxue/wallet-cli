package org.tron.common.crypto.chacha20poly1305;

import java.util.Arrays;
import org.tron.common.crypto.digital.UnsignedInt;
import org.tron.common.crypto.digital.UnsignedShort;

public class Poly1305 {

  private static final int Poly1305KeySize = 32;
  private static final int Poly1305TagSize = 16;
  private byte[] buffer;
  private int leftover;
  private boolean finished;
  private UnsignedShort[] r;
  private UnsignedShort[] h;
  private UnsignedShort[] pad;

  private UnsignedShort readUInt16LE(byte[] a, int offset) {
    byte[] b = Arrays.copyOfRange(a, offset, offset + 2);
    byte t = b[0];
    b[0] = b[1];
    b[1] = t;
    return new UnsignedShort(b);
  }

  private void writeUInt16LE(byte[] m, int offset, UnsignedShort a) {
    byte[] b = a.toByteArray();
    m[offset++] = b[1];
    m[offset++] = b[0];
  }

  public Poly1305(byte[] key) {
    this.buffer = new byte[16];
    this.leftover = 0;
    this.r = new UnsignedShort[10];
    this.h = new UnsignedShort[10];
    this.pad = new UnsignedShort[8];
    this.finished = false;

    UnsignedShort[] t = new UnsignedShort[8];
    int i;

    for (i = 7; i >= 0; i--) {
      t[i] = readUInt16LE(key, i * 2);
    }

    this.r[0] = t[0].AND(0x1fff);
    this.r[1] = t[0].rightShift(13).OR(t[1].leftShift(3)).AND(0x1fff);
    this.r[2] = t[1].rightShift(10).OR(t[2].leftShift(6)).AND(0x1f03);
    this.r[3] = t[2].rightShift(7).OR(t[3].leftShift(9)).AND(0x1fff);
    this.r[4] = t[3].rightShift(4).OR(t[4].leftShift(12)).AND(0x00ff);
    this.r[5] = t[4].rightShift(1).AND(0x1ffe);
    this.r[6] = t[4].rightShift(14).OR(t[5].leftShift(2)).AND(0x1fff);
    this.r[7] = t[5].rightShift(11).OR(t[6].leftShift(5)).AND(0x1f81);
    this.r[8] = t[6].rightShift(8).OR(t[7].leftShift(8)).AND(0x1fff);
    this.r[9] = t[7].rightShift(5).AND(0x007f);

    for (i = 7; i >= 0; i--) {
      this.h[i] = new UnsignedShort(0);
      this.pad[i] = readUInt16LE(key, 16 + (2 * i));
    }
    this.h[8] = new UnsignedShort(0);
    this.h[9] = new UnsignedShort(0);
    this.leftover = 0;
    this.finished = false;
  }

  public void blocks(byte[] m, int mpos, int bytes) {
    UnsignedShort hibit = this.finished ? new UnsignedShort(0) : new UnsignedShort(1 << 11);
    UnsignedShort[] t = new UnsignedShort[8];
    UnsignedInt[] d = new UnsignedInt[10];
    int i, j;
    while (bytes >= 16) {
      for (i = 7; i >= 0; i--) {
        t[i] = readUInt16LE(m, i * 2 + mpos);
      }

      this.h[0] = this.h[0].ADD(t[0].AND(0x1fff));
      this.h[1] = this.h[1].ADD(t[0].rightShift(13).OR(t[1].leftShift(3)).AND(0x1fff));
      this.h[2] = this.h[2].ADD(t[1].rightShift(10).OR(t[2].leftShift(6)).AND(0x1fff));
      this.h[3] = this.h[3].ADD(t[2].rightShift(7).OR(t[3].leftShift(9)).AND(0x1fff));
      this.h[4] = this.h[4].ADD(t[3].rightShift(4).OR(t[4].leftShift(12)).AND(0x1fff));
      this.h[5] = this.h[5].ADD(t[4].rightShift(1).AND(0x1fff));
      this.h[6] = this.h[6].ADD(t[4].rightShift(14).OR(t[5].leftShift(2)).AND(0x1fff));
      this.h[7] = this.h[7].ADD(t[5].rightShift(11).OR(t[6].leftShift(5)).AND(0x1fff));
      this.h[8] = this.h[8].ADD(t[6].rightShift(8).OR(t[7].leftShift(8)).AND(0x1fff));
      this.h[9] = this.h[9].ADD(t[7].rightShift(5).OR(hibit));

      UnsignedInt c = new UnsignedInt(0);
      for (i = 0; i < 10; i++) {
        d[i] = c;
        for (j = 0; j < 10; j++) {
          long temp = d[i].toLong() + this.h[j].toLong() * ((j <= i) ? this.r[i - j].toLong()
              : 5 * this.r[i + 10 - j].toLong());
          d[i] = new UnsignedInt(temp);
          if (j == 4) {
            c = d[i].rightShift(13);
            d[i] = d[i].AND(0x1fff);
          }
        }
        c = c.ADD(d[i].rightShift(13));
        d[i] = d[i].AND(0x1fff);
      }

      c = c.leftShift(2).ADD(c);
      c = c.ADD(d[0]);
      d[0] = c.AND(0x1fff);
      c = c.rightShift(13);
      d[1] = d[1].ADD(c);
      for (i = 9; i >= 0; i--) {
        this.h[i] = new UnsignedShort(d[i].toLong());
      }
      mpos += 16;
      bytes -= 16;
    }
  }

  public void update(byte[] m, int bytes) {
    int want, i, mpos = 0;
    if (this.leftover > 0) {
      want = 16 - this.leftover;
      if (want > bytes) {
        want = bytes;
      }
      for (i = want - 1; i > 0; i--) {
        this.buffer[this.leftover + i] = m[i + mpos];
      }
      bytes -= want;
      mpos += want;
      this.leftover += want;
      if (this.leftover < 16) {
        return;
      }
      this.blocks(this.buffer, 0, 16);
      this.leftover = 0;
    }

    if (bytes >= 16) {
      want = (bytes & ~(16 - 1));
      this.blocks(m, mpos, want);
      mpos += want;
      bytes -= want;
    }

    if (bytes > 0) {
      for (i = bytes - 1; i >= 0; i--) {
        this.buffer[this.leftover + i] = m[i + mpos];
      }
      this.leftover += bytes;
    }
    return;
  }

  public byte[] finish() {
    byte[] mac = new byte[16];
    UnsignedShort[] g = new UnsignedShort[10];
    UnsignedShort c;
    UnsignedShort mask;
    UnsignedInt f;
    int i;
    if (this.leftover > 0) {
      i = this.leftover;
      this.buffer[i++] = 1;
      for (; i < 16; i++) {
        this.buffer[i] = 0;
      }
      this.finished = true;
      this.blocks(this.buffer, 0, 16);
    }

    c = this.h[1].rightShift(13);
    this.h[1] = this.h[1].AND(0x1fff);
    for (i = 2; i < 10; i++) {
      this.h[i] = this.h[i].ADD(c);
      c = this.h[i].rightShift(13);
      this.h[i] = this.h[i].AND(0x1fff);
    }
    long temp = this.h[0].toLong() + (c.toLong() * 5);
    this.h[0] = new UnsignedShort(temp);
    c = this.h[0].rightShift(13);
    this.h[0] = this.h[0].AND(0x1fff);
    this.h[1] = this.h[1].ADD(c);
    c = this.h[1].rightShift(13);
    this.h[1] = this.h[1].AND(0x1fff);
    this.h[2] = this.h[2].ADD(c);

    g[0] = this.h[0].ADD(5);
    c = g[0].rightShift(13);
    g[0] = g[0].AND(0x1fff);
    for (i = 1; i < 10; i++) {
      g[i] = this.h[i].ADD(c);
      c = g[i].rightShift(13);
      g[i] = g[i].AND(0x1fff);
    }
    g[9] = g[9].SUB(1 << 13);

    mask = g[9].rightShift(15).SUB(1);
    for (i = 9; i >= 0; i--) {
      g[i] = g[i].AND(mask);
    }
    mask = mask.NON();
    for (i = 9; i > 0; i--) {
      this.h[i] = this.h[i].AND(mask).OR(g[i]);
    }
    this.h[0] = this.h[0].OR(this.h[1].leftShift(13));
    this.h[1] = this.h[1].rightShift(3).OR(this.h[2].leftShift(10));
    this.h[2] = this.h[2].rightShift(6).OR(this.h[3].leftShift(7));
    this.h[3] = this.h[3].rightShift(9).OR(this.h[4].leftShift(4));
    this.h[4] = this.h[4].rightShift(12).OR(this.h[5].leftShift(1)).OR(this.h[6].leftShift(14));
    this.h[5] = this.h[6].rightShift(2).OR(this.h[7].leftShift(11));
    this.h[6] = this.h[7].rightShift(5).OR(this.h[8].leftShift(8));
    this.h[7] = this.h[8].rightShift(8).OR(this.h[9].leftShift(5));

    f = new UnsignedInt(this.h[0].ADD(this.pad[0]).toLong());
    this.h[0] = new UnsignedShort(f.toLong());
    for (i = 1; i < 8; i++) {
      f = new UnsignedInt(this.h[i].toLong() + this.pad[i].toLong() + f.rightShift(16).toLong());
      this.h[i] = new UnsignedShort(f.toLong());
    }

    for (i = 7; i >= 0; i--) {
      writeUInt16LE(mac, i * 2, this.h[i]);
      this.pad[i] = new UnsignedShort(0);
    }
    for (i = 9; i >= 0; i--) {
      this.h[i] = new UnsignedShort(0);
      this.r[i] = new UnsignedShort(0);
    }

    return mac;
  }

  public static byte[] poly1305_auth(byte[] m, int len ,byte[] key) {
    Poly1305 ctx = new Poly1305(key);
    ctx.update(m, len);
    return ctx.finish();
  }
}
