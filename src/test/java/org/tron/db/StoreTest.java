package org.tron.db;

import java.io.File;
import java.util.Optional;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.tron.api.GrpcAPI.BlockList;
import org.tron.api.GrpcAPI.BlockList.Builder;
import org.tron.common.application.Application;
import org.tron.common.application.ApplicationFactory;
import org.tron.common.application.TronApplicationContext;
import org.tron.common.utils.FileUtil;
import org.tron.common.zksnark.ReceiverZkHelper;
import org.tron.core.config.DefaultConfig;
import org.tron.core.db.Manager;
import org.tron.protos.Contract.SHA256Compress;
import org.tron.core.capsule.IncrementalMerkleTreeCapsule;
import org.tron.core.db.impl.IncrementalMerkleTreeStore;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.DynamicProperties;
import org.tron.protos.Protocol.TransactionInfo;
import org.tron.protos.Protocol.TransactionInfoOrBuilder;
import org.tron.walletserver.WalletApi;

public class StoreTest {

  private static Manager dbManager;
  private static TronApplicationContext context;
  private static String dbPath = "output_StoreAPI_test";
  private static Application AppT;


  static {
    context = new TronApplicationContext(DefaultConfig.class);
    AppT = ApplicationFactory.create(context);
  }

  @BeforeClass
  public static void init() {
    dbManager = context.getBean(Manager.class);
  }

  @AfterClass
  public static void removeDb() {
    AppT.shutdown();
    context.destroy();
    FileUtil.deleteDir(new File(dbPath));
  }

  @Test
  public void testGetCurrentTxBlockNumber() {
    ReceiverZkHelper helper = new ReceiverZkHelper(dbManager) {

      @Override
      protected Optional<TransactionInfo> getTransactionInfoById(String txid) {
        return Optional.of(TransactionInfo.newBuilder().setBlockNumber(100).build());
      }

      @Override
      protected Optional<DynamicProperties> getDynamicProperties() {
        return Optional.of(DynamicProperties.newBuilder().setLastSolidityBlockNum(90).build());
      }
    };
    String txid = "txid";
    Assert.assertEquals(100, helper.getCurrentTxBlockNumber(txid));
  }

  @Test
  public void testProcess1() {
    long localBlockNum = 0;
    dbManager.getDynamicPropertiesStore().saveLatestWitnessBlockNumber(localBlockNum);
    ReceiverZkHelper helper = new ReceiverZkHelper(dbManager) {
      @Override
      protected Optional<BlockList> getBlockByLimitNext(long localBlockNum,
          long currentTxBlockNumber) {
        Builder blockListBuilder = BlockList.newBuilder();
        for (long i = localBlockNum + 1; i <= currentTxBlockNumber; i++) {
          Block build = Block.newBuilder().build();
          blockListBuilder.addBlock(build);
        }
        return Optional.of(blockListBuilder.build());
      }
    };

  }

  @Test
  public void testProcess2() {
    long localBlockNum = 200;

  }

  //  @Test
  public void test() {
    IncrementalMerkleTreeStore merkleTreeStore = dbManager.getMerkleTreeStore();
    IncrementalMerkleTreeCapsule capsule = new IncrementalMerkleTreeCapsule();
    capsule.addParents(SHA256Compress.newBuilder().build());
    byte[] key = {0x01};
    merkleTreeStore.put(key, capsule);
    IncrementalMerkleTreeCapsule result = merkleTreeStore.get(key);

    String dbName = merkleTreeStore.getDbName();
    System.out.println(dbName);
  }


}
