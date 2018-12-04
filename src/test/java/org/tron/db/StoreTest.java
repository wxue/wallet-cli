package org.tron.db;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
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
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.FileUtil;
import org.tron.common.zksnark.ReceiverZkHelper;
import org.tron.common.zksnark.merkle.IncrementalMerkleTreeContainer;
import org.tron.common.zksnark.merkle.IncrementalMerkleWitnessContainer;
import org.tron.core.capsule.SHA256CompressCapsule;
import org.tron.core.config.DefaultConfig;
import org.tron.core.db.Manager;
import org.tron.protos.Contract.SHA256Compress;
import org.tron.core.capsule.IncrementalMerkleTreeCapsule;
import org.tron.core.db.impl.IncrementalMerkleTreeStore;
import org.tron.protos.Contract.ZksnarkV0TransferContract;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.DynamicProperties;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.Protocol.TransactionInfo;
import org.tron.walletserver.WalletApi;

public class StoreTest {

  private static Manager dbManager;
  private static TronApplicationContext context;
  private static String dbPath = "output_StoreAPI_test";//todo 目录问题
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

//  @Test
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

  private Transaction createTransaction(String strCm1, String strCm2) {
    ByteString cm1 = ByteString.copyFrom(ByteArray.fromHexString(strCm1));
    ByteString cm2 = ByteString.copyFrom(ByteArray.fromHexString(strCm2));
    ZksnarkV0TransferContract contract = ZksnarkV0TransferContract.newBuilder().setCm1(cm1)
        .setCm2(cm2).build();
    Transaction.raw.Builder transactionBuilder = Transaction.raw.newBuilder().addContract(
        Transaction.Contract.newBuilder().setType(ContractType.ZksnarkV0TransferContract)
            .setParameter(
                Any.pack(contract)).build());
    Transaction transaction = Transaction.newBuilder().setRawData(transactionBuilder.build())
        .build();
    return transaction;
  }


  //two block,each block has one transaction,the second block is the currentTxBlock .
  @Test
  public void testProcess1() throws Exception {
    String txid = "8a489c426b49683787117755e99c80095be19ba1a2cc437236d11473c8ef3739";
    long currentTxBlockNumber = 100L;//test processing two block
    long localBlockNum = 98L;

    //init tree and witness
    IncrementalMerkleTreeContainer tree = new IncrementalMerkleTreeContainer(
        new IncrementalMerkleTreeCapsule());

    String s1 = "2ec45f5ae2d1bc7a80df02abfb2814a1239f956c6fb3ac0e112c008ba2c1ab91";
    SHA256CompressCapsule compressCapsule1 = new SHA256CompressCapsule();
    compressCapsule1.setContent(ByteString.copyFrom(ByteArray.fromHexString(s1)));
    SHA256Compress a = compressCapsule1.getInstance();

    tree.append(a);
    IncrementalMerkleWitnessContainer witness1 = tree.toWitness();
    byte[] key = {0x01};
    dbManager.getMerkleWitnessStore().put(key, witness1.getWitnessCapsule());

    dbManager.getMerkleContainer().setCurrentMerkle(tree);
    dbManager.getMerkleContainer().saveCurrentMerkleTreeAsBestMerkleTree();
    dbManager.getTreeBlockIndexStore()
        .put(localBlockNum, dbManager.getMerkleContainer().getBestMerkle().getMerkleTreeKey());
    dbManager.getDynamicPropertiesStore()
        .saveLatestWitnessBlockNumber(localBlockNum);

    //create extend ReceiverZkHelper
    ReceiverZkHelper helper = new ReceiverZkHelper(dbManager) {
      @Override
      protected Optional<BlockList> getBlockByLimitNext(long localBlockNum,
          long currentTxBlockNumber) {
        String cm1 = "2ec45f5ae2d1bc7a80df02abfb2814a1239f956c6fb3ac0e112c008ba2c1ab91";
        String cm2 = "2ec45f5ae2d1bc7a80df02abfb2814a1239f956c6fb3ac0e112c008ba2c1ab92";
        Transaction transaction1 = createTransaction(cm1, cm2);
        String cm3 = "3daa00c9a1966a37531c829b9b1cd928f8172d35174e1aecd31ba0ed36863017";
        String cm4 = "3daa00c9a1966a37531c829b9b1cd928f8172d35174e1aecd31ba0ed36863018";
        Transaction transaction2 = createTransaction(cm3, cm4);

        Builder blockListBuilder = BlockList.newBuilder();
        Block build1 = Block.newBuilder().addTransactions(0, transaction1).build();
        Block build2 = Block.newBuilder().addTransactions(0, transaction2).build();
        blockListBuilder.addBlock(build1).addBlock(build2);
        return Optional.of(blockListBuilder.build());
      }
    };
    //test
    helper.processCase1(txid, localBlockNum, currentTxBlockNumber);

    //verify
    Assert.assertEquals(3, dbManager.getMerkleWitnessStore().getAllWitness().size());
    dbManager.getMerkleWitnessStore().getAllWitness().forEach(wit -> {
      Assert.assertEquals(5, wit.size());
    });

    Assert.assertEquals(5, dbManager.getMerkleContainer().getCurrentMerkle().size());
    Assert.assertEquals(5, dbManager.getMerkleContainer().getBestMerkle().size());
    Assert.assertNotNull(dbManager.getTreeBlockIndexStore().get(98L));
    Assert.assertNotNull(dbManager.getTreeBlockIndexStore().get(99L));
    Assert.assertNotNull(dbManager.getTreeBlockIndexStore().get(100L));
    Assert.assertEquals(3, dbManager.getTreeBlockIndexStore().size());
    Assert.assertEquals(100L, dbManager.getDynamicPropertiesStore().getLatestWitnessBlockNumber());
  }

  //two block,each block has one transaction,the first block is the currentTxBlock .
//  @Test
  public void testProcess2() throws Exception {
    String txid = "5d36032d035301b4816cc0fd443b2fa3ed22a99099363173691863a5343b31b4";
    long currentTxBlockNumber = 99L;//test processing two block
    long localBlockNum = 100L;

    //init tree and witness
    IncrementalMerkleTreeContainer tree = new IncrementalMerkleTreeContainer(
        new IncrementalMerkleTreeCapsule());

    String s1 = "2ec45f5ae2d1bc7a80df02abfb2814a1239f956c6fb3ac0e112c008ba2c1ab91";
    SHA256CompressCapsule compressCapsule1 = new SHA256CompressCapsule();
    compressCapsule1.setContent(ByteString.copyFrom(ByteArray.fromHexString(s1)));
    SHA256Compress a = compressCapsule1.getInstance();
    tree.append(a);
    dbManager.getMerkleTreeStore().put(tree.getMerkleTreeKey(), tree.getTreeCapsule());
    //todo：Initialized here, only the case where the currentTxBlockNumber is included locally, and the case where currentTxBlockNumber is not included is to be added.
    dbManager.getTreeBlockIndexStore()
        .put(currentTxBlockNumber - 1, tree.getMerkleTreeKey());

    //create extend ReceiverZkHelper
    ReceiverZkHelper helper = new ReceiverZkHelper(dbManager) {
      @Override
      protected Optional<BlockList> getBlockByLimitNext(long localBlockNum,
          long currentTxBlockNumber) {
        String cm1 = "2ec45f5ae2d1bc7a80df02abfb2814a1239f956c6fb3ac0e112c008ba2c1ab91";
        String cm2 = "2ec45f5ae2d1bc7a80df02abfb2814a1239f956c6fb3ac0e112c008ba2c1ab92";
        Transaction transaction1 = createTransaction(cm1, cm2);

        Builder blockListBuilder = BlockList.newBuilder();
        Block build1 = Block.newBuilder().addTransactions(0, transaction1).build();
        blockListBuilder.addBlock(build1);
        return Optional.of(blockListBuilder.build());
      }

      @Override
      public Block getBlock(long blockNum) {
        //two transaction,the first transaction is the currentTransaction
        String cm1 = "2ec45f5ae2d1bc7a80df02abfb2814a1239f956c6fb3ac0e112c008ba2c1ab93";
        String cm2 = "2ec45f5ae2d1bc7a80df02abfb2814a1239f956c6fb3ac0e112c008ba2c1ab94";
        Transaction transaction1 = createTransaction(cm1, cm2);
        String cm3 = "3daa00c9a1966a37531c829b9b1cd928f8172d35174e1aecd31ba0ed36863019";
        String cm4 = "3daa00c9a1966a37531c829b9b1cd928f8172d35174e1aecd31ba0ed36863020";
        Transaction transaction2 = createTransaction(cm3, cm4);

        Block build1 = Block.newBuilder().addTransactions(0, transaction1)
            .addTransactions(1, transaction2).build();
        return build1;
      }
    };
    //test
    helper.processCase2(txid, localBlockNum, currentTxBlockNumber);

    //verify
    Assert.assertEquals(2, dbManager.getMerkleWitnessStore().getAllWitness().size());
    dbManager.getMerkleWitnessStore().getAllWitness().forEach(wit -> {
      Assert.assertEquals(1 + 4 + 2, wit.size());
    });


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
