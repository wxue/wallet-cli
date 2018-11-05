package org.tron.demo;

import com.google.protobuf.ByteString;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import org.tron.common.crypto.eddsa.spec.EdDSANamedCurveSpec;
import org.tron.common.crypto.eddsa.spec.EdDSANamedCurveTable;
import org.tron.common.crypto.eddsa.spec.EdDSAParameterSpec;
import org.tron.common.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import org.tron.common.utils.ByteArray;
import org.tron.common.crypto.eddsa.EdDSAEngine;
import org.tron.common.crypto.eddsa.EdDSAPrivateKey;
import org.tron.common.crypto.eddsa.EdDSAPublicKey;
import org.tron.common.crypto.eddsa.KeyPairGenerator;
import org.tron.common.crypto.eddsa.MathUtils;
import org.tron.common.crypto.eddsa.math.GroupElement;
import org.tron.common.utils.ZksnarkUtils;
import org.tron.protos.Contract.ZksnarkV0TransferContract;
import org.tron.protos.Protocol.Transaction;
import org.tron.walletserver.WalletApi;

public class ZksnarkTransferDemo {

  public static Transaction createZksnarkTransfer0() {
    ZksnarkV0TransferContract.Builder zkBuilder = ZksnarkV0TransferContract.newBuilder();
    zkBuilder.setVFromPub(100_000_000L);
    zkBuilder.setOwnerAddress(
        ByteString.copyFrom(WalletApi.decodeFromBase58Check("TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW")));
    zkBuilder.setVToPub(0);
    zkBuilder.setToAddress(ByteString.EMPTY);

    return null;
  }

  public static void testGenKey(){
    KeyPairGenerator generator = new KeyPairGenerator();
    KeyPair keyPairA = generator.generateKeyPair();

    PrivateKey privateKeyA = keyPairA.getPrivate();
    PublicKey publickeyA = keyPairA.getPublic();
    GroupElement A = ((EdDSAPublicKey)(publickeyA)).getA();
    byte[] a = ((EdDSAPrivateKey)(privateKeyA)).geta();

    EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
    GroupElement A2 = MathUtils.scalarMultiplyGroupElement(ed25519.getB(), MathUtils.toFieldElement(MathUtils.toBigInteger(a)));

    byte[] A1 = generator.getPubkey(a);


    KeyPair keyPairB = generator.generateKeyPair();

    PrivateKey privateKeyB = keyPairB.getPrivate();
    PublicKey publickeyB = keyPairB.getPublic();

    GroupElement B = ((EdDSAPublicKey)(publickeyB)).getA();
    byte[] b = ((EdDSAPrivateKey)(privateKeyB)).geta();


    GroupElement C = MathUtils.scalarMultiplyGroupElement(B, MathUtils.toFieldElement(MathUtils.toBigInteger(a)));
    GroupElement C1 = MathUtils.scalarMultiplyGroupElement(A, MathUtils.toFieldElement(MathUtils.toBigInteger(b)));
  //  GroupElement C = B.scalarMultiply(a);
   // GroupElement C1 = A.scalarMultiply(b);

    System.out.println(ByteArray.toHexString(A.toByteArray()));
    System.out.println(ByteArray.toHexString(a));
    System.out.println(ByteArray.toHexString(A1));
    System.out.println(ByteArray.toHexString(A2.toByteArray()));

    

    System.out.println(ByteArray.toHexString(B.toByteArray()));
    System.out.println(ByteArray.toHexString(b));
    System.out.println(ByteArray.toHexString(C.toByteArray()));
    System.out.println(ByteArray.toHexString(C1.toByteArray()));




    EdDSAEngine engine = new EdDSAEngine();
    try {
      engine.initSign(privateKeyA);
      byte[] sign = engine.signOneShot("just test 1".getBytes());
      System.out.println(ByteArray.toHexString(sign));

      engine.initVerify(publickeyA);
      boolean r =  engine.verifyOneShot("just test 1".getBytes(), sign);
      System.out.println(r);

      engine.initSign(privateKeyA);
      engine.update("just test 1".getBytes());
      byte[] sign1 = engine.sign();
      System.out.println(ByteArray.toHexString(sign1));

      PublicKey publicKeyA1 = ZksnarkUtils.byte2PublicKey(A1);
      engine.initVerify(publicKeyA1);
      engine.update("just test 1".getBytes());
      boolean r1 = engine.verify(sign1);
      System.out.println(r1);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    } catch (SignatureException e) {
      e.printStackTrace();
    }

  }

  public static void main(String[] args) {
    testGenKey();
  }
}
