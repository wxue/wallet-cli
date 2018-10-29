package org.tron.demo;

import com.google.protobuf.ByteString;
import org.tron.common.utils.ByteArray;
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

  public static void main(String[] args) {
  }
}
