package org.tron.demo;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import java.util.Arrays;
import org.tron.api.GrpcAPI.AddressPrKeyPairMessage;
import org.tron.api.GrpcAPI.EasyTransferResponse;
import org.tron.api.GrpcAPI.Return;
import org.tron.api.GrpcAPI.TransactionExtention;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.Sha256Hash;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Utils;
import org.tron.protos.Contract;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.Transaction;
import org.tron.walletserver.WalletClient;

public class OfflineApiDemo {

  private static byte[] getAddressByPassphrase(String passPhrase) {
    byte[] privateKey = Sha256Hash.hash(passPhrase.getBytes());
    ECKey ecKey = ECKey.fromPrivate(privateKey);
    byte[] address = ecKey.getAddress();
    return address;
  }

  public static Transaction createTransaction(byte[] from, byte[] to, long amount) {
    Transaction.Builder transactionBuilder = Transaction.newBuilder();
    Transaction.Contract.Builder contractBuilder = Transaction.Contract.newBuilder();
    Contract.TransferContract.Builder transferContractBuilder = Contract.TransferContract
        .newBuilder();
    transferContractBuilder.setAmount(amount);
    ByteString bsTo = ByteString.copyFrom(to);
    ByteString bsOwner = ByteString.copyFrom(from);
    transferContractBuilder.setToAddress(bsTo);
    transferContractBuilder.setOwnerAddress(bsOwner);
    try {
      Any any = Any.pack(transferContractBuilder.build());
      contractBuilder.setParameter(any);
    } catch (Exception e) {
      return null;
    }
    contractBuilder.setType(Transaction.Contract.ContractType.TransferContract);
    transactionBuilder.getRawDataBuilder().addContract(contractBuilder)
        .setTimestamp(System.currentTimeMillis())
        .setExpiration(System.currentTimeMillis() + 10 * 60 * 60 * 1000);
    Transaction transaction = transactionBuilder.build();
//    Transaction refTransaction = setReference(transaction, newestBlock);
//    return refTransaction;
    return transaction;  // just for test sign. So need not setReference.If broadcast this transaction to fullnode will faild.
  }

  private static void testTransactionSign() {
    String privateStr = "D95611A9AF2A2A45359106222ED1AFED48853D9A44DEFF8DC7913F5CBA727366";
    byte[] privateBytes = ByteArray.fromHexString(privateStr);
    ECKey ecKey = ECKey.fromPrivate(privateBytes);
    byte[] from = ecKey.getAddress();
    byte[] to = WalletClient.decodeFromBase58Check("TGehVcNhud84JDCGrNHKVz9jEAVKUpbuiv");
    long amount = 100_000_000L; //100 TRX, api only receive trx in drop, and 1 trx = 1000000 drop
    Transaction transaction = createTransaction(from, to, amount);

    TransactionExtention transactionExtention = WalletClient
        .signTransactionByApi2(transaction, ecKey.getPrivKeyBytes());
    if (transactionExtention == null) {
      System.out.println("transactionExtention is null");
      return;
    }
    Return ret = transactionExtention.getResult();
    if (!ret.getResult()) {
      System.out.println("Code = " + ret.getCode());
      System.out.println("Message = " + ret.getMessage().toStringUtf8());
      return;
    }
    System.out.println(Utils.printTransaction(transactionExtention));
  }

  public static void main(String[] args) {
    String passPhrase = "test pass phrase";
    byte[] address = WalletClient.createAdresss(passPhrase.getBytes());
    if (!Arrays.equals(address, getAddressByPassphrase(passPhrase))) {
      System.out.println("The address is diffrent !!");
    }
    System.out
        .printf("passPhrase = %s ; address = %s\n", passPhrase,
            WalletClient.encode58Check(address));

    AddressPrKeyPairMessage addressPrKeyPairMessage = WalletClient.generateAddress();
    System.out
        .printf("privatekey = %s ; address = %s\n", addressPrKeyPairMessage.getPrivateKey(),
            addressPrKeyPairMessage.getAddress());

    testTransactionSign();
  }
}
