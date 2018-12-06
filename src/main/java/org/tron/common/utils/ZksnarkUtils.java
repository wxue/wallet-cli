/*
 * java-tron is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * java-tron is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.tron.common.utils;

import com.google.protobuf.ByteString;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Optional;
import java.util.Random;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.tron.api.GrpcAPI.BytesMessage;
import org.tron.api.ZkGrpcAPI.IncrementalMerkleTreeMsg;
import org.tron.api.ZkGrpcAPI.IncrementalWitnessMsg;
import org.tron.api.ZkGrpcAPI.JSInputMsg;
import org.tron.api.ZkGrpcAPI.JSOutputMsg;
import org.tron.api.ZkGrpcAPI.SproutNoteMsg;
import org.tron.api.ZkGrpcAPI.Uint256Msg;
import org.tron.common.crypto.Sha256Hash;
import org.tron.common.crypto.blake2b.Blake2b;
import org.tron.common.crypto.chacha20poly1305.ChaCha20.WrongKeySizeException;
import org.tron.common.crypto.chacha20poly1305.ChaCha20.WrongNonceSizeException;
import org.tron.common.crypto.chacha20poly1305.ChaCha20Poly1305aead.WrongPolyMac;
import org.tron.common.crypto.dh25519.MontgomeryOperations;
import org.tron.common.crypto.eddsa.EdDSAPublicKey;
import org.tron.common.crypto.eddsa.spec.EdDSANamedCurveSpec;
import org.tron.common.crypto.eddsa.spec.EdDSANamedCurveTable;
import org.tron.common.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.tron.common.zksnark.CmUtils.CmTuple;
import org.tron.common.zksnark.Prf;
import org.tron.common.zksnark.ShieldAddressGenerator;
import org.tron.core.exception.CipherException;
import org.tron.protos.Contract.BN128G1;
import org.tron.protos.Contract.BN128G2;
import org.tron.protos.Contract.IncrementalMerkleTree;
import org.tron.protos.Contract.IncrementalMerkleWitness;
import org.tron.protos.Contract.SHA256Compress;
import org.tron.protos.Contract.ZksnarkV0TransferContract;
import org.tron.protos.Contract.zkv0proof;
import org.tron.walletserver.ShiledWalletFile;
import org.tron.common.crypto.chacha20poly1305.*;
import org.tron.walletserver.WalletApi;

public class ZksnarkUtils {

  public static byte[] computeHSig(org.tron.protos.Contract.ZksnarkV0TransferContract zkContract) {
    byte[] message = ByteUtil
        .merge(zkContract.getRandomSeed().toByteArray(), zkContract.getNf1().toByteArray(),
            zkContract.getNf2().toByteArray(), zkContract.getPksig().toByteArray());
    byte[] personal = {'T', 'r', 'o', 'n', 'C', 'o', 'm', 'p', 'u', 't', 'e', 'h', 'S', 'i', 'g',
        '0'};
    return Blake2b.blake2b_personal(message, personal);
  }

  public static byte[] computeZkSignInput(ZksnarkV0TransferContract zkContract) {
    byte[] hSig = computeHSig(zkContract);
    ZksnarkV0TransferContract.Builder builder = zkContract.toBuilder();
    builder.setRandomSeed(ByteString.EMPTY);
    builder.setPksig(ByteString.copyFrom(hSig));
    return builder.build().toByteArray();
  }

  public static EdDSAPublicKey byte2PublicKey(byte[] pk) {
    EdDSANamedCurveSpec curveSpec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
    EdDSAPublicKeySpec spec = new EdDSAPublicKeySpec(pk, curveSpec);
    EdDSAPublicKey publicKey = new EdDSAPublicKey(spec);
    return publicKey;
  }

  public static JSOutputMsg computeOutputMsg(byte[] to, long v, String memo) {
    JSOutputMsg.Builder output = JSOutputMsg.newBuilder();
    if (ArrayUtils.isEmpty(to) || to.length != 64) {
      ShieldAddressGenerator shieldAddressGenerator = new ShieldAddressGenerator();
      byte[] privateKey = shieldAddressGenerator.generatePrivateKey();
      byte[] publicKey = shieldAddressGenerator.generatePublicKey(privateKey);

      byte[] privateKeyEnc = shieldAddressGenerator.generatePrivateKeyEnc(privateKey);
      byte[] publicKeyEnc = shieldAddressGenerator.generatePublicKeyEnc(privateKeyEnc);
      to = ByteUtil.merge(publicKey, publicKeyEnc);
      v = 0;
    }

    output.setAPk(
        Uint256Msg.newBuilder().setHash(ByteString.copyFrom(Arrays.copyOfRange(to, 0, 32))));
    output.setPkEnc(
        Uint256Msg.newBuilder().setHash(ByteString.copyFrom(Arrays.copyOfRange(to, 32, 64))));
    output.setValue(v);

    if (StringUtils.isEmpty(memo)) {
      memo = "Default memo";
    }
    output.setMemo(ByteString.copyFromUtf8(memo));
    return output.build();
  }

  public static JSInputMsg CmTuple2JSInputMsg(CmTuple in, IncrementalWitnessMsg witnessMsg) {
    JSInputMsg.Builder input = JSInputMsg.newBuilder();
    SproutNoteMsg.Builder note = SproutNoteMsg.newBuilder();
    byte[] ask;
    byte[] apk;
    long v;
    byte[] rho;
    byte[] r;

    org.tron.common.zksnark.ShieldAddressGenerator shieldAddressGenerator = new ShieldAddressGenerator();
    if (in == null) {
      ask = shieldAddressGenerator.generatePrivateKey();
      apk = shieldAddressGenerator.generatePublicKey(ask);
      v = 0;
      rho = new byte[32];
      new Random().nextBytes(rho);
      r = new byte[32];
      new Random().nextBytes(r);
//      input.setWitness(witnessMsg);
    } else {
      ask = Arrays.copyOfRange(in.getAddr_sk(), 0, 32);
      apk = Arrays.copyOfRange(in.getAddr_pk(), 0, 32);
      v = ByteArray.toLong(in.getV());
      rho = in.getRho();
      r = in.getR();
      input.setWitness(witnessMsg);
    }
    note.setValue(v);
    note.setAPk(Uint256Msg.newBuilder().setHash(ByteString.copyFrom(apk)));
    note.setRho(Uint256Msg.newBuilder().setHash(ByteString.copyFrom(rho)));
    note.setR(Uint256Msg.newBuilder().setHash(ByteString.copyFrom(r)));
    input.setKey(Uint256Msg.newBuilder().setHash(ByteString.copyFrom(ask)));
    input.setNote(note);
    return input.build();
  }

  public static Uint256Msg SHA256Compress2Uint256Msg(SHA256Compress c) {
    ByteString fb = c.getContent();
    Uint256Msg.Builder msg = Uint256Msg.newBuilder();
    msg.setHash(fb);
    return msg.build();
  }

  public static IncrementalMerkleTreeMsg transferTree(IncrementalMerkleTree tree) {
    IncrementalMerkleTreeMsg.Builder builder = IncrementalMerkleTreeMsg.newBuilder();
    builder.setRight(SHA256Compress2Uint256Msg(tree.getRight()));
    builder.setLeft(SHA256Compress2Uint256Msg(tree.getLeft()));
    for (int i = 0; i < tree.getParentsCount(); i++) {
      builder.addParents(SHA256Compress2Uint256Msg(tree.getParents(i)));
    }
    return builder.build();
  }

  public static IncrementalWitnessMsg MerkleWitness2IncrementalWitness(
      IncrementalMerkleWitness witnessMsg) {
    IncrementalWitnessMsg.Builder builder = IncrementalWitnessMsg.newBuilder();
    builder.setTree(transferTree(witnessMsg.getTree()));
    for (int i = 0; i < witnessMsg.getFilledCount(); i++) {
      SHA256Compress f = witnessMsg.getFilled(i);
      builder.addFilled(SHA256Compress2Uint256Msg(f));
    }
    builder.setCursor(transferTree(witnessMsg.getCursor()));
    builder.setCursorDepth((int) witnessMsg.getCursorDepth());
    return builder.build();
  }

  // return g*f.
  public static byte[] scalarMultiply(byte[] g, byte[] f) {
    byte[] output = new byte[32];
    MontgomeryOperations.scalarmult(output, 0, f, 0, g, 0);
    return output;
  }

  public static byte[] encrypt(byte[] plain, byte[] key, byte[] nonce) {
    try {
      byte[] result = new byte[plain.length + 16];
      ChaCha20Poly1305aead.chacha20poly1305Encrypt(null, key, nonce, result, plain);
      return result;
    } catch (WrongKeySizeException e) {
      e.printStackTrace();
    } catch (WrongNonceSizeException e) {
      e.printStackTrace();
    }
    return null;
  }


  public static byte[] decrypt(byte[] cipher, byte[] key, byte[] nonce) {
    try {
      byte[] result = new byte[cipher.length];
      ChaCha20Poly1305aead.chacha20poly1305Decrypt(null, key, nonce, result, cipher);
      return result;
    } catch (WrongKeySizeException e) {
      e.printStackTrace();
    } catch (WrongNonceSizeException e) {
      e.printStackTrace();
    } catch (WrongPolyMac wrongPolyMac) {
      System.out.println("wrongPolyMac");
    }
    return null;
  }

  public static byte[] KDF(byte[] dh, byte[] epk, byte[] pkEnc, byte[] hSig, byte nonce) {
    byte[] personal = new byte[]{'T', 'r', 'o', 'n', 'K', 'D', 'F', 0, nonce, 0, 0, 0, 0,
        0, 0, 0};
    byte[] input = ByteUtil.merge(hSig, dh, epk, pkEnc);
    return Blake2b.blake2b_personal(input, personal);
  }

//  private static byte[] getContractId(ZksnarkV0TransferContract contract) {
//    return Sha256Hash.of(contract.toByteArray()).getBytes();
//  }

  private static CmTuple decrypC(int index, byte[] txIx, byte[] K, byte[] cipher,
      byte[] cm,
      byte[] publicAddress, byte[] privateAddress) {
    byte[] none = new byte[12];
    byte[] plain = decrypt(cipher, K, none);
    if (ArrayUtils.isEmpty(plain)) {
      return null;
    }
    if (plain[0] != 0) {
      return null;
    }
    byte[] v = Arrays.copyOfRange(plain, 1, 9);
    sort(v);
    System.out
        .println("You recive " + ByteArray.toLong(v) + " sun. cm is " + ByteArray.toHexString(cm));
    byte[] rho = Arrays.copyOfRange(plain, 9, 41);
    byte[] r = Arrays.copyOfRange(plain, 41, 73);
    CmTuple cmTuple = new CmTuple(cm, publicAddress, privateAddress, v, rho, r, index,
        txIx);
    return cmTuple;
  }

  public static byte[] NoteCommit(byte[] apk, byte[] v, byte[] rho, byte[] r) {
    byte[] leadByte = new byte[1];
    leadByte[0] = (byte) 0xB0;
    byte[] v1 = Arrays.copyOf(v, v.length);
    sort(v1);
    byte[] input = ByteUtil.merge(leadByte, apk, v1, rho, r);
    return Sha256Hash.hash(input);
  }

  private static boolean checkCmTuple(CmTuple cmTuple) {
    byte[] cm = NoteCommit(Arrays.copyOfRange(cmTuple.getAddr_pk(), 0, 32), cmTuple.getV(),
        cmTuple.getRho(), cmTuple.getR());
    if (!Arrays.equals(cm, cmTuple.getCm())) {
      System.out.println("Cm is wrong!");
      return false;
    }

    byte[] nf = Prf.prfNf(Arrays.copyOfRange(cmTuple.getAddr_sk(), 0, 32), cmTuple.getRho());
    Optional<BytesMessage> ret = WalletApi.getNullifier(ByteArray.toHexString(nf));
    if (ret.isPresent() && !ret.get().getValue().isEmpty()) {
      System.out.println(ByteArray.toHexString(nf) + " is exist!");
      return false;
    }

    return true;
  }

  public static boolean saveShieldCoin(ZksnarkV0TransferContract contract, ShiledWalletFile
      shiled, String txId)
      throws CipherException {
    byte[] privateAddress = shiled.getPrivateAddress();
    if (ArrayUtils.isEmpty(privateAddress) || privateAddress.length != 64) {
      return false;
    }
    byte[] publicAddress = shiled.getPublicAddress();
    if (ArrayUtils.isEmpty(publicAddress) || publicAddress.length != 64) {
      return false;
    }

    byte[] skEnc = Arrays.copyOfRange(privateAddress, 32, 64);
    byte[] pkEnc = Arrays.copyOfRange(publicAddress, 32, 64);

    byte[] hSig = computeHSig(contract);
    byte[] epk = contract.getEpk().toByteArray();
    byte[] dh = scalarMultiply(epk, skEnc);

    byte[] K = KDF(dh, epk, pkEnc, hSig, (byte) (0));
    byte[] cipher = contract.getC1().toByteArray();
    byte[] cm = contract.getCm1().toByteArray();

    boolean result = false;
    CmTuple cmTuple = decrypC(1, ByteArray.fromHexString(txId), K, cipher, cm, publicAddress,
        privateAddress);
    if (cmTuple != null) {
      if (!checkCmTuple(cmTuple)) {
        return false;
      }
      result = true;
      shiled.saveCm(cmTuple);
    }
    K = KDF(dh, epk, pkEnc, hSig, (byte) (1));
    cipher = contract.getC2().toByteArray();
    cm = contract.getCm2().toByteArray();
    cmTuple = decrypC(2, ByteArray.fromHexString(txId), K, cipher, cm, publicAddress,
        privateAddress);
    if (cmTuple != null) {
      if (!checkCmTuple(cmTuple)) {
        return false;
      }
      result = true;
      shiled.saveCm(cmTuple);
    }
    return result;
  }

  public static BN128G1 byte2BN128G1(byte[] x, byte[] y) {
    BN128G1.Builder g = BN128G1.newBuilder();
    g.setX(ByteString.copyFrom(x));
    g.setY(ByteString.copyFrom(y));
    return g.build();
  }

  public static BN128G2 byte2BN128G2(byte[] x1, byte[] x2, byte[] y1, byte[] y2) {
    BN128G2.Builder g = BN128G2.newBuilder();
    g.setX1(ByteString.copyFrom(x1));
    g.setX2(ByteString.copyFrom(x2));
    g.setY1(ByteString.copyFrom(y1));
    g.setY2(ByteString.copyFrom(y2));
    return g.build();
  }

  public static zkv0proof byte2Proof() {
    byte[] A_x = ByteArray
        .fromHexString("33a136eeec333ade7220f2edd31831c746387d408c3a4b4a037633ac6ed34500");
    byte[] A_y = ByteArray
        .fromHexString("79864cdc727acd414a0c52b499ed6177b396b1ef3a00b9d35c95f38363b18300");
    byte[] Apx = ByteArray
        .fromHexString("8a54aaadf72d160bd35e378d81ddb4010c7d2ff1338124ca363199dec4b04a27");
    byte[] Apy = ByteArray
        .fromHexString("1b20622b8fb37c10e6314cf2855c5c32710abc372cf699f0476829129140ec2a");
    byte[] Bx1 = ByteArray
        .fromHexString("a80054b2e8165eefe2b7f2f46d2ef4a856b856af0f2334400526ed618e6c1a1f");
    byte[] Bx2 = ByteArray
        .fromHexString("9df591cf83e4c9c154e1422a4349f12c876ab8409e4b0e2187e47b6c23a1241e");
    byte[] By1 = ByteArray
        .fromHexString("593bb3f3289fe84c7bafe380a87164ed4d9697aa05cc2a4fc25019c8a5505d0f");
    byte[] By2 = ByteArray
        .fromHexString("18778d6f8d86bdd05bb2bd43f387ff47fac0b08ed0780636b16f87501485d128");
    byte[] Bpx = ByteArray
        .fromHexString("fa28556841537a26ac53801c6957a4577abe1ec2913705756bae26bf8f87712f");
    byte[] Bpy = ByteArray
        .fromHexString("afed07fdce070d9b8571aec139e6b804d14215a583adcdf702107eaac1f42430");
    byte[] C_x = ByteArray
        .fromHexString("c71fa429ce9e1cb1db789216e23cf4e14c38bb9155aa10f75c346a9bc47ebf23");
    byte[] C_y = ByteArray
        .fromHexString("aa9c3ca79a78d2211802085889c6b42273ce927dd42eeec2931d3a4c1614de2e");
    byte[] Cpx = ByteArray
        .fromHexString("52551f640fd5cd2063afa213c66e67b09d3ae5fad3a2197a4b674bfb0e652f08");
    byte[] Cpy = ByteArray
        .fromHexString("1a2ef609b18d24e85a2c51c8f0ad375513c554a2e221b98b6e1c846f116bff1b");
    byte[] H_x = ByteArray
        .fromHexString("50fbe75c882dc061df33639b8269b4a6325486bc43392f66fa9608f213006c00");
    byte[] H_y = ByteArray
        .fromHexString("23e3ed09748ef6c41467e6c3dd16381cac95e5ef64e6849443af69491de74f11");
    byte[] K_x = ByteArray
        .fromHexString("8062bd4273594950690073a9bfa9179e6c95d9252fe1d0435f4d6dc11af06f1b");
    byte[] K_y = ByteArray
        .fromHexString("45c42e7e5027f40ac8116229b545d005056b7a19394e11b62c83fce46691c00d");
    zkv0proof.Builder builder = zkv0proof.newBuilder();
    builder.setA(byte2BN128G1(A_x, A_y));
    builder.setAP(byte2BN128G1(Apx, Apy));
    builder.setB(byte2BN128G2(Bx1, Bx2, By1, By2));
    builder.setBP(byte2BN128G1(Bpx, Bpy));
    builder.setC(byte2BN128G1(C_x, C_y));
    builder.setCP(byte2BN128G1(Cpx, Cpy));
    builder.setH(byte2BN128G1(H_x, H_y));
    builder.setK(byte2BN128G1(K_x, K_y));
    return builder.build();
  }

  public static void sort(byte[] bytes) {
    int len = bytes.length / 2;
    for (int i = 0; i < len; i++) {
      byte b = bytes[i];
      bytes[i] = bytes[bytes.length - i - 1];
      bytes[bytes.length - i - 1] = b;
    }
  }

  public static zkv0proof byte2Proof(byte[] in) {
    System.out.println(ByteArray.toHexString(in));
    if (ArrayUtils.isEmpty(in) || in.length != 584) {
      return null;
    }
    zkv0proof.Builder builder = zkv0proof.newBuilder();
    int offset = 1;
    byte[] Ax = Arrays.copyOfRange(in, offset, offset + 32);
    sort(Ax);
    byte[] Ay = Arrays.copyOfRange(in, offset + 32, offset + 64);
    sort(Ay);
    offset += 64;
    offset++;
    byte[] Apx = Arrays.copyOfRange(in, offset, offset + 32);
    sort(Apx);
    byte[] Apy = Arrays.copyOfRange(in, offset + 32, offset + 64);
    sort(Apy);
    offset += 64;
    offset++;
    byte[] Bx2 = Arrays.copyOfRange(in, offset, offset + 32);
    sort(Bx2);
    byte[] Bx1 = Arrays.copyOfRange(in, offset + 32, offset + 64);
    sort(Bx1);
    byte[] By2 = Arrays.copyOfRange(in, offset + 64, offset + 96);
    sort(By2);
    byte[] By1 = Arrays.copyOfRange(in, offset + 96, offset + 128);
    sort(By1);
    offset += 128;
    offset++;
    byte[] Bpx = Arrays.copyOfRange(in, offset, offset + 32);
    sort(Bpx);
    byte[] Bpy = Arrays.copyOfRange(in, offset + 32, offset + 64);
    sort(Bpy);
    offset += 64;
    offset++;
    byte[] Cx = Arrays.copyOfRange(in, offset, offset + 32);
    sort(Cx);
    byte[] Cy = Arrays.copyOfRange(in, offset + 32, offset + 64);
    sort(Cy);
    offset += 64;
    offset++;
    byte[] Cpx = Arrays.copyOfRange(in, offset, offset + 32);
    sort(Cpx);
    byte[] Cpy = Arrays.copyOfRange(in, offset + 32, offset + 64);
    sort(Cpy);
    offset += 64;
    offset++;
    byte[] Hx = Arrays.copyOfRange(in, offset, offset + 32);
    sort(Hx);
    byte[] Hy = Arrays.copyOfRange(in, offset + 32, offset + 64);
    sort(Hy);
    offset += 64;
    offset++;
    byte[] Kx = Arrays.copyOfRange(in, offset, offset + 32);
    sort(Kx);
    byte[] Ky = Arrays.copyOfRange(in, offset + 32, offset + 64);
    sort(Ky);
    builder
        .setA(BN128G1.newBuilder().setX(ByteString.copyFrom(Ax)).setY(ByteString.copyFrom(Ay)));
    builder
        .setAP(
            BN128G1.newBuilder().setX(ByteString.copyFrom(Apx)).setY(ByteString.copyFrom(Apy)));
    builder
        .setB(
            BN128G2.newBuilder().setX1(ByteString.copyFrom(Bx1)).setX2(ByteString.copyFrom(Bx2))
                .setY1(ByteString.copyFrom(By1)).setY2(ByteString.copyFrom(By2)));
    builder
        .setBP(
            BN128G1.newBuilder().setX(ByteString.copyFrom(Bpx)).setY(ByteString.copyFrom(Bpy)));
    builder
        .setC(BN128G1.newBuilder().setX(ByteString.copyFrom(Cx)).setY(ByteString.copyFrom(Cy)));
    builder
        .setCP(
            BN128G1.newBuilder().setX(ByteString.copyFrom(Cpx)).setY(ByteString.copyFrom(Cpy)));
    builder
        .setK(BN128G1.newBuilder().setX(ByteString.copyFrom(Kx)).setY(ByteString.copyFrom(Ky)));
    builder
        .setH(BN128G1.newBuilder().setX(ByteString.copyFrom(Hx)).setY(ByteString.copyFrom(Hy)));
    return builder.build();
  }

  public static void main(String[] args) {
//    byte[] dh = ByteArray
//        .fromHexString("18397f4eacec172efeeb353f1819d86b2605f1797f29da1733ecdcd1ea03410c");
//    byte[] pkEnc = ByteArray
//        .fromHexString("66b42bbaac6949b9687dd562724635d5a5b20dc063ebd346b76050f7877d1501");
//    byte[] hSig = ByteArray
//        .fromHexString("9611a84e1869c23aa3f935ea296e8746caea4595ec69b2da2eed89e11aaadf30");
//    byte[] epk = ByteArray
//        .fromHexString("361847b08ff84a2ec6f34d9afb91c3f408b495576814cc79812e884b6ce1082c");
//
//    sort(dh);
//    sort(epk);
//    sort(pkEnc);
//    sort(hSig);
//    byte[] K = KDF(dh, epk, pkEnc, hSig, (byte) 1);
//    System.out.println(ByteArray.toHexString(K));

//    byte[] K = ByteArray.fromHexString("2605F56488A8F0102B02185F9DD83BA33BC0E86D3D5FD1A3C966976B3C49567A");
//
//  //  sort(K);
//    byte[] cipher = ByteArray.fromHexString(
//        "DE9DC4DF75758B3E7355D290828EA86CA9E52F838300F8C68FF2253D4F9395EFCA060EC3E47114E7A102835720CEF8EADDB8869A5E84D8AB8D45931E9015A8DAB3D9EDE0B9589D56A5F65F45F6D71CFEB763B83DA4B0C9B14455F612129E12EABEE9565095420AC80A6F58E93810D78A1A4D51BB961A7CF32CBA09CC77D597446BD139D58E9208A07132B16B1779A0280FAC322BBB9E5DC52FA68DB1297AF4819C9A2119FC3DED5D790F529CEF1AEE08347666368883CCE3001D5BA2B9FEB56AD58D48208A2AB9F120BD97FA9550DC5E10502C29A4B0F17505ABCA687F4E9EAACC437F067FF38862F2519B0EC1D3B94CE65F62F584CD44E2F96BE654D885806BE1F54D5FCC5675B7A75BBE4B2DF80FA8BB74308BD1649FD5E94CFB8057B30A10CCCCECD36FB73197587FE53AA7A9B7AA116179ACF6CD7B144C265DBFEBAEEB2CCA2620937CF3655FCA4E4421E8A763E3BDD8A6362B00FCB33CBA538CA08103928D40A7017608C1801751BDC94A4F97D80E8C6EAC5DA438692919557685CDF2BE07E8AE90F47F9DCF49952458F6A2FA7C945669D9FDC4D5DB4C3A161A64C9603296846E713EAA4D276CBC5BC13864DFFBDE995A9452CB77C7CFEBFEFB3E5B43E2504CF20726B7744D0D8CD1D242BF5459711DCC6B46445A7B6A9AE4235A52CF21DF3AFCFD8D4AEFC370DEB8A4FF14D10A0BF88333B4BA3DB1647644231AF1C3AB99E39AA367AB7A8AF704C3354C634C956DEA97F08092E03542A5B80A78DBBC5C160D1371A9345C76A981A298FA4DF556F4DCA80C4AD7C3046685547D0D907F0BC06244154984E3D5A5F39AFB9E6FFFA08EFFE143D85C20FDD6");
//    byte[] plain = ByteArray.fromHexString(
//        "0000E1F50500000000DD8332767E1DC920C43266EC984DE2DC87ADD757A2850FFACF6A4D3D1DC6FEE025E37D61EFC6E15D65C691AD6C8AF6AA200BCCEE33839B968C5EA7A2F33D2E8B4F75742031000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
//    byte[] none = new byte[12];
//    byte[] text;
//    text = decrypt(cipher, K, none, 1);
//    System.out.println(ByteArray.toHexString(text));
//    text = encrypt(plain, K, none, 1);
//    System.out.println(ByteArray.toHexString(text));
    byte[] sk = ByteArray
        .fromHexString("90030e70ffb713aee6364a4ba7055efdb88dba0b3f793d1466f55d74375439ff");
    byte[] PK = ShieldAddressGenerator.generatePublicKeyEnc(sk);
    System.out.println(ByteArray.toHexString(PK));
    sort(sk);

    PK = ShieldAddressGenerator.generatePublicKeyEnc(sk);
    System.out.println(ByteArray.toHexString(PK));

    PK = ShieldAddressGenerator.generatePublicKeyEnc(sk);
    System.out.println(ByteArray.toHexString(PK));
//
    byte[] epk = ByteArray
        .fromHexString("361847b08ff84a2ec6f34d9afb91c3f408b495576814cc79812e884b6ce1082c");
    byte[] skEnc = ByteArray
        .fromHexString("5C919EE7C8356B534846626C8D97876BF3B736232BB85664172C7EB677E76CEE");
    sort(epk);
    byte[] pk_enc = ByteArray
        .fromHexString("66b42bbaac6949b9687dd562724635d5a5b20dc063ebd346b76050f7877d1501");
    sort(pk_enc);
    byte[] dh = scalarMultiply(pk_enc, sk);
    System.out.println(ByteArray.toHexString(dh));


  }
}
