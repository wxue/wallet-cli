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
import java.util.Arrays;
import java.util.Random;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.tron.api.ZkGrpcAPI.CompressedG;
import org.tron.api.ZkGrpcAPI.IncrementalMerkleTreeMsg;
import org.tron.api.ZkGrpcAPI.IncrementalWitnessMsg;
import org.tron.api.ZkGrpcAPI.JSInputMsg;
import org.tron.api.ZkGrpcAPI.JSOutputMsg;
import org.tron.api.ZkGrpcAPI.ProofMsg;
import org.tron.api.ZkGrpcAPI.SproutNoteMsg;
import org.tron.api.ZkGrpcAPI.Uint256Msg;
import org.tron.common.crypto.blake2b.Blake2b;
import org.tron.common.crypto.blake2b.security.Blake2b256Digest;
import org.tron.common.crypto.eddsa.EdDSAPublicKey;
import org.tron.common.crypto.eddsa.MathUtils;
import org.tron.common.crypto.eddsa.math.FieldElement;
import org.tron.common.crypto.eddsa.math.GroupElement;
import org.tron.common.crypto.eddsa.spec.EdDSANamedCurveSpec;
import org.tron.common.crypto.eddsa.spec.EdDSANamedCurveTable;
import org.tron.common.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.tron.common.zksnark.CmUtils.CmTuple;
import org.tron.common.zksnark.ShieldAddressGenerator;
import org.tron.protos.Contract.BN128G1;
import org.tron.protos.Contract.BN128G2;
import org.tron.protos.Contract.ZksnarkV0TransferContract;
import org.tron.protos.Contract.zkv0proof;
import org.tron.walletserver.WalletApi;
import org.tron.common.crypto.chacha20.*;

public class ZksnarkUtils {

  public static byte[] computeHSig(org.tron.protos.Contract.ZksnarkV0TransferContract zkContract) {
    byte[] message = ByteUtil
        .merge(zkContract.getRandomSeed().toByteArray(), zkContract.getNf1().toByteArray(),
            zkContract.getNf2().toByteArray(), zkContract.getPksig().toByteArray());
    byte[] personal = {'Z', 'c', 'a', 's', 'h', 'C', 'o', 'm', 'p', 'u', 't', 'e', 'h', 'S', 'i',
        'g'};
    System.out.println(ByteArray.toHexString(message));
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
      ask = in.addr_sk;
      apk = in.addr_pk;
      v = ByteArray.toLong(in.v);
      rho = in.rho;
      r = in.r;
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

  public static IncrementalWitnessMsg GetEmptyWitness() {
    IncrementalWitnessMsg.Builder builder = IncrementalWitnessMsg.newBuilder();
    IncrementalMerkleTreeMsg.Builder merkle = IncrementalMerkleTreeMsg.newBuilder();
    byte[] temp = new byte[32];
    new Random().nextBytes(temp);

    merkle.setLeft(Uint256Msg.newBuilder().setHash(ByteString.copyFrom(temp)));
    merkle.setRight(Uint256Msg.newBuilder().setHash(ByteString.copyFrom(temp)));
    merkle.addEmptyroots(Uint256Msg.newBuilder().setHash(ByteString.copyFrom(temp)));
    merkle.addParents(Uint256Msg.newBuilder().setHash(ByteString.copyFrom(temp)));
    builder.setTree(merkle);
    builder.setCursor(merkle);
    builder.addFilled(Uint256Msg.newBuilder().setHash(ByteString.copyFrom(temp)));
    builder.setCursorDepth(0);
    return builder.build();
//    message IncrementalMerkleTreeMsg {
//      repeated Uint256Msg emptyroots = 1; // 静态变量，后期考虑不要了，直接去掉，不用传递TODO
//      Uint256Msg left = 2;
//      Uint256Msg right = 3;
//      repeated Uint256Msg parents = 4;
//    }
//
//    message IncrementalWitnessMsg {
//      IncrementalMerkleTreeMsg tree = 1;
//      repeated Uint256Msg filled = 2;
//      IncrementalMerkleTreeMsg cursor = 3;
//      uint32 cursor_depth = 4;
//    }
  }

  public static IncrementalWitnessMsg MerkleWitness2IncrementalWitness() {
    return null;
  }

  // return g*f.
  public static byte[] scalarMultiply(byte[] g, byte[] f) {
    GroupElement G = byte2PublicKey(g).getA();
    FieldElement F = MathUtils.toFieldElement(MathUtils.toBigInteger(f));
    return MathUtils.scalarMultiplyGroupElement(G, F).toByteArray();
  }

  public static byte[] KDF() {
    return null;
  }

  public static byte[] encrypt_decrypt(byte[] plain, byte[] key, byte[] nonce, int counter) {
    byte[] result = new byte[plain.length];
    try {
      ChaCha20 cipher = new ChaCha20(key, nonce, counter);
      cipher.encrypt(result, plain, plain.length);
    } catch (Exception e) {
      System.out.println(e.getMessage());
    }
    return result;
  }


  public static boolean saveShieldCoin(ZksnarkV0TransferContract contract, String address,
      int index) {
    byte[] privateAddress = WalletApi.decodeBase58Check(address);
    if (ArrayUtils.isEmpty(privateAddress) || privateAddress.length != 64) {
      return false;
    }
    byte[] ask = Arrays.copyOfRange(privateAddress, 0, 32);
    byte[] skEnc = Arrays.copyOfRange(privateAddress, 32, 64);
    byte[] apk = ShieldAddressGenerator.generatePublicKey(ask);
    byte[] pkEnc = ShieldAddressGenerator.generatePublicKeyEnc(skEnc);
    byte[] addressPub = ByteUtil.merge(apk, pkEnc);

    byte[] nf = index == 1 ? contract.getNf1().toByteArray() : contract.getNf2().toByteArray();
    //TODO: check nf
    byte[] prefix = "ZcashKDF".getBytes();
    byte[] i = new byte[1];
    i[0] = (byte) (index - 1);
    byte[] zero = new byte[7];
    byte[] hSig = computeHSig(contract);
    byte[] epk = contract.getEpk().toByteArray();
    byte[] dh = scalarMultiply(epk, skEnc);
    byte[] input = ByteUtil.merge(prefix, i, zero, hSig, dh, epk, pkEnc);
    byte[] K1 = Blake2b.hash(input);
    byte[] none = new byte[12];
    byte[] cipher = index == 1 ? contract.getC1().toByteArray() : contract.getC2().toByteArray();
    byte[] plain = encrypt_decrypt(cipher, K1, none, 1);
    byte[] cm = index == 1 ? contract.getCm1().toByteArray() : contract.getCm2().toByteArray();
    byte[] v = Arrays.copyOfRange(plain, 0, 8);
    byte[] rho = Arrays.copyOfRange(plain, 8, 16);
    byte[] r = Arrays.copyOfRange(plain, 16, 24);
    CmTuple cmTuple = new CmTuple(cm, addressPub, privateAddress, v, rho, r);
    //TODO: save cmTuple
    return true;
  }

  public static BN128G1 compressedG2BN128G1(CompressedG c) {
    BN128G1.Builder b = BN128G1.newBuilder();
    byte[] d = c.getData().toByteArray();
    b.setX(ByteString.copyFrom(Arrays.copyOfRange(d, 0, 32)));
    b.setY(ByteString.copyFrom(Arrays.copyOfRange(d, 32, 64)));
    return b.build();
  }

  public static BN128G2 compressedG2BN128G2(CompressedG c) {
    BN128G2.Builder b = BN128G2.newBuilder();
    byte[] d = c.getData().toByteArray();
    b.setX1(ByteString.copyFrom(Arrays.copyOfRange(d, 0, 32)));
    b.setX2(ByteString.copyFrom(Arrays.copyOfRange(d, 32, 64)));
    b.setY1(ByteString.copyFrom(Arrays.copyOfRange(d, 64, 96)));
    b.setY2(ByteString.copyFrom(Arrays.copyOfRange(d, 96, 128)));
    return b.build();
  }

  public static zkv0proof proofMsg2Proof(ProofMsg in) {
    zkv0proof.Builder builder = zkv0proof.newBuilder();

    builder.setA(compressedG2BN128G1(in.getGA()));
    builder.setAP(compressedG2BN128G1(in.getGAPrime()));
    builder.setB(compressedG2BN128G2(in.getGB()));
    builder.setBP(compressedG2BN128G1(in.getGBPrime()));
    builder.setC(compressedG2BN128G1(in.getGC()));
    builder.setCP(compressedG2BN128G1(in.getGCPrime()));
    builder.setH(compressedG2BN128G1(in.getGH()));
    builder.setK(compressedG2BN128G1(in.getGK()));

    return builder.build();
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
    builder.setA(BN128G1.newBuilder().setX(ByteString.copyFrom(Ax)).setY(ByteString.copyFrom(Ay)));
    builder
        .setAP(BN128G1.newBuilder().setX(ByteString.copyFrom(Apx)).setY(ByteString.copyFrom(Apy)));
    builder
        .setB(BN128G2.newBuilder().setX1(ByteString.copyFrom(Bx1)).setX2(ByteString.copyFrom(Bx2))
            .setY1(ByteString.copyFrom(By1)).setY2(ByteString.copyFrom(By2)));
    builder
        .setBP(BN128G1.newBuilder().setX(ByteString.copyFrom(Bpx)).setY(ByteString.copyFrom(Bpy)));
    builder.setC(BN128G1.newBuilder().setX(ByteString.copyFrom(Cx)).setY(ByteString.copyFrom(Cy)));
    builder
        .setCP(BN128G1.newBuilder().setX(ByteString.copyFrom(Cpx)).setY(ByteString.copyFrom(Cpy)));
    builder.setK(BN128G1.newBuilder().setX(ByteString.copyFrom(Kx)).setY(ByteString.copyFrom(Ky)));
    builder.setH(BN128G1.newBuilder().setX(ByteString.copyFrom(Hx)).setY(ByteString.copyFrom(Hy)));
    return builder.build();
  }
}
