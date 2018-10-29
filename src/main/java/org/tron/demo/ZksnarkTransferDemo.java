package org.tron.demo;

import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.tron.common.utils.ByteArray;
import org.tron.eddsa.EdDSAPrivateKey;
import org.tron.eddsa.EdDSAPublicKey;
import org.tron.eddsa.KeyPairGenerator;
import org.tron.eddsa.MathUtils;
import org.tron.eddsa.math.GroupElement;
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
    System.out.println(ByteArray.toHexString(B.toByteArray()));
    System.out.println(ByteArray.toHexString(b));
    System.out.println(ByteArray.toHexString(C.toByteArray()));
    System.out.println(ByteArray.toHexString(C1.toByteArray()));

  }

  public static void main(String[] args) {
    testGenKey();
  }
}
