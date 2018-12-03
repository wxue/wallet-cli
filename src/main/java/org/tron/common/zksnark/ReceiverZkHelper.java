package org.tron.common.zksnark;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.tron.api.GrpcAPI.BlockList;
import org.tron.common.crypto.Sha256Hash;
import org.tron.common.utils.ByteArray;
import org.tron.common.zksnark.merkle.IncrementalMerkleTreeContainer;
import org.tron.common.zksnark.merkle.IncrementalMerkleWitnessContainer;
import org.tron.core.capsule.IncrementalMerkleTreeCapsule;
import org.tron.core.capsule.IncrementalMerkleWitnessCapsule;
import org.tron.core.capsule.SHA256CompressCapsule;
import org.tron.core.db.Manager;
import org.tron.core.exception.ItemNotFoundException;
import org.tron.protos.Contract.SHA256Compress;
import org.tron.protos.Contract.ZksnarkV0TransferContract;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.DynamicProperties;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Transaction.Contract;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.Protocol.TransactionInfo;
import org.tron.walletserver.WalletApi;

@Slf4j
public class ReceiverZkHelper {

  private Manager dbManager;

  public ReceiverZkHelper(Manager dbManager) {
    this.dbManager = dbManager;
  }

  public boolean syncAndUpdateWitness(String txid)
      throws InvalidProtocolBufferException, ItemNotFoundException {

    long currentTxBlockNumber = getCurrentTxBlockNumber(txid);
    if (currentTxBlockNumber < 0) {
      return false;
    }

    long localBlockNum = getLatestWitnessBlockNumber(currentTxBlockNumber);
    if (localBlockNum < 0) {
      return false;
    }

    if (localBlockNum < currentTxBlockNumber) {
      return processCase1(txid, localBlockNum, currentTxBlockNumber);
    } else {
      return processCase2(txid, currentTxBlockNumber, localBlockNum);
    }

  }

  protected long getLatestWitnessBlockNumber(long currentTxBlockNumber) {
    long localBlockNum = dbManager.getDynamicPropertiesStore()
        .getLatestWitnessBlockNumber();
    if (localBlockNum == 0) {
      if (!getAndSaveBestMerkleTree(currentTxBlockNumber)) {
        log.error("getAndSaveBestMerkleTree error");
        return -1;
      }
      localBlockNum = currentTxBlockNumber - 1;
    }
    return localBlockNum;
  }

  protected boolean getAndSaveBestMerkleTree(long currentTxBlockNumber) {
//    WalletApi.getBestMerkleTree(currentTxBlockNumber-1); todo
    IncrementalMerkleTreeContainer treeContainer = null;
    dbManager.getMerkleContainer().setCurrentMerkle(treeContainer);
    dbManager.getMerkleContainer().saveCurrentMerkleTreeAsBestMerkleTree();
    dbManager.getTreeBlockIndexStore()
        .put(currentTxBlockNumber - 1,
            dbManager.getMerkleContainer().getBestMerkle().getMerkleTreeKey());
    dbManager.getDynamicPropertiesStore()
        .saveLatestWitnessBlockNumber(currentTxBlockNumber - 1);
    return true;
  }

  protected Optional<TransactionInfo> getTransactionInfoById(String txid) {
    return WalletApi.getTransactionInfoById(txid);
  }

  protected Optional<DynamicProperties> getDynamicProperties() {
    return WalletApi.getDynamicProperties();
  }

  protected Optional<BlockList> getBlockByLimitNext(long localBlockNum, long currentTxBlockNumber) {
    Optional<BlockList> blocksOption = WalletApi
        .getBlockByLimitNext(localBlockNum + 1, currentTxBlockNumber);

    //todo：1、分段查询。2、提供接口，仅返回包含匿名交易的块
    if (!blocksOption.isPresent()) {
      log.error("getBlock error !!");
      return Optional.empty();
    }

    BlockList blockList = blocksOption.get();

    if (blockList.getBlockList().size() != (currentTxBlockNumber - localBlockNum)) {
      log
          .error("num error,blockList:" + blockList.getBlockList().size() + ",localBlockNum:"
              + localBlockNum + ",currentTxBlockNumber:" + currentTxBlockNumber);
    }

    return blocksOption;
  }

  public long getCurrentTxBlockNumber(String txid) {
    Optional<TransactionInfo> transactionInfoById = getTransactionInfoById(txid);
    if (!transactionInfoById.isPresent()) {
      System.out.println("TransactionInfo not exists !!");
      return -1;
    }
    TransactionInfo transactionInfo = transactionInfoById.get();
    long currentTxBlockNumber = transactionInfo.getBlockNumber();
    Optional<DynamicProperties> dynamicPropertiesOptional = getDynamicProperties();
    if (!dynamicPropertiesOptional.isPresent()) {
      System.out.println("DynamicProperties not exists !!");
      return -1;
    }
    DynamicProperties dynamicProperties = dynamicPropertiesOptional.get();
    long lastSolidityBlockNum = dynamicProperties.getLastSolidityBlockNum();
    if (currentTxBlockNumber < lastSolidityBlockNum) {
      System.out.println("block is not solidify yet!!");
      return -1;
    }
    return currentTxBlockNumber;
  }

  public boolean processCase1(String txid, long localBlockNum,
      long currentTxBlockNumber) throws InvalidProtocolBufferException, ItemNotFoundException {

    log.info(
        "start to sync block,localBlockNum < currentTxBlockNumber,localBlockNum:" + localBlockNum
            + ",currentTxBlockNumber:"
            + currentTxBlockNumber);
    //需要更新已有的witness、tree
    Optional<BlockList> blocksOption = getBlockByLimitNext(localBlockNum + 1, currentTxBlockNumber);

    if (!blocksOption.isPresent()) {
      return false;
    }

    IncrementalMerkleTreeContainer tree = dbManager.getMerkleContainer()
        .getCurrentMerkle();

    boolean found = false;

    for (Block block : blocksOption.get().getBlockList()) {
      for (Transaction transaction1 : block.getTransactionsList()) {

        Contract contract1 = transaction1.getRawData().getContract(0);
        if (contract1.getType() == ContractType.ZksnarkV0TransferContract) {
          ZksnarkV0TransferContract zkContract = contract1.getParameter()
              .unpack(ZksnarkV0TransferContract.class);

          //getAllWitness，并存入cm（待优化，只更新未使用的witness）
          SHA256CompressCapsule cmCapsule1 = new SHA256CompressCapsule();
          cmCapsule1.setContent(zkContract.getCm1());
          SHA256Compress cm1 = cmCapsule1.getInstance();

          SHA256CompressCapsule cmCapsule2 = new SHA256CompressCapsule();
          cmCapsule2.setContent(zkContract.getCm2());
          SHA256Compress cm2 = cmCapsule2.getInstance();

          //witness的写入可以优化
          Iterator<Entry<byte[], IncrementalMerkleWitnessCapsule>> iterator = dbManager
              .getMerkleWitnessStore().iterator();
          System.out.println( "merkleWitnessStore:"+ dbManager.getMerkleWitnessStore().size());
          while (iterator.hasNext()) {
            Entry<byte[], IncrementalMerkleWitnessCapsule> entry = iterator.next();
            IncrementalMerkleWitnessContainer container = entry.getValue()
                .toMerkleWitnessContainer();
            System.out.println( "witness before:"+ container.getWitnessCapsule().size());
            container.append(cm1);
            container.append(cm2);
            System.out.println( "witness after:"+ container.getWitnessCapsule().size());
            dbManager.getMerkleWitnessStore()
                .put(entry.getKey(), container.getWitnessCapsule());
          }

          //当cm equels 当前cm时，tree "toWitness"，并 witnessList.add(witness);
          //todo，如果cm时需要记录的
          ByteString contractId = ByteString.copyFrom(getContractId(zkContract));
          System.out.println( "treeSizeBefore:"+ tree.size());
          if (foundTx(transaction1, txid)) {
            found = true;
            tree.append(cm1);
            IncrementalMerkleWitnessContainer witness1 = tree.getTreeCapsule().deepCopy()
                .toMerkleTreeContainer().toWitness();
            witness1.getWitnessCapsule().setOutputPoint(contractId, 0);

            witness1.append(cm2);
            tree.append(cm2);

            IncrementalMerkleWitnessContainer witness2 = tree.getTreeCapsule().deepCopy()
                .toMerkleTreeContainer().toWitness();
            witness2.getWitnessCapsule().setOutputPoint(contractId, 1);
            System.out.println( "witness1 size after:"+ witness1.getWitnessCapsule().size());
            System.out.println( "witness2 size after:"+ witness2.getWitnessCapsule().size());
            dbManager
                .getMerkleWitnessStore()
                .put(witness1.getMerkleWitnessKey(), witness1.getWitnessCapsule());
            dbManager
                .getMerkleWitnessStore()
                .put(witness2.getMerkleWitnessKey(), witness2.getWitnessCapsule());
          } else {
            tree.append(cm1);
            tree.append(cm2);
          }

          System.out.println( "treeSizeAfter:"+ tree.size());
          //每一个交易，存一次currentTree
          dbManager.getMerkleContainer().setCurrentMerkle(tree);

        }
      }

      //每一个块，存一次currentTree
      dbManager.getMerkleContainer().saveCurrentMerkleTreeAsBestMerkleTree();
      dbManager.getTreeBlockIndexStore()
          .put(++localBlockNum,
              dbManager.getMerkleContainer().getBestMerkle().getMerkleTreeKey());

    }

    dbManager.getDynamicPropertiesStore().saveLatestWitnessBlockNumber(currentTxBlockNumber);
    if (!found) {
      log.warn("not found valid cm");
      return false;
    }

    return true;
  }

  private static boolean foundTx(Transaction transaction, String txId) {
    ByteString byteString = getTransactionId(transaction).getByteString();

    return ByteArray.toHexString(byteString.toByteArray()).equals(txId);

  }

  private boolean processCase2(String txid, long localBlockNum,
      long currentTxBlockNumber) throws InvalidProtocolBufferException, ItemNotFoundException {

    log.info(
        "start to sync block,localBlockNum >= currentTxBlockNumber,localBlockNum:" + localBlockNum
            + ",currentTxBlockNumber:" + currentTxBlockNumber);

    //不需要更新已有的witness、tree
    //todo ,单独处理交易对应witness（需要优化）
    //需要拿到前一个块的tree（blockNum到treeKey的映射关系），并获得这个块的所有匿名交易

    //先需要校验第一个块是否有该witness , 然后依此获得后续块
    Block block = WalletApi.getBlock(currentTxBlockNumber);
    if (block == null) {
      log.error("getBlock error !!");
      return false;
    }

    byte[] key = dbManager.getTreeBlockIndexStore().get(currentTxBlockNumber - 1);
    IncrementalMerkleTreeContainer tree = dbManager.getMerkleTreeStore()
        .get(key).toMerkleTreeContainer();

    List<IncrementalMerkleWitnessContainer> newWitness = new ArrayList<>();

    boolean found = false;

    for (Transaction transaction1 : block.getTransactionsList()) {

      Contract contract1 = transaction1.getRawData().getContract(0);
      if (contract1.getType() == ContractType.ZksnarkV0TransferContract) {
        ZksnarkV0TransferContract zkContract = contract1.getParameter()
            .unpack(ZksnarkV0TransferContract.class);

        //getAllWitness，并存入cm（待优化，只更新未使用的witness）
        SHA256CompressCapsule cmCapsule1 = new SHA256CompressCapsule();
        cmCapsule1.setContent(zkContract.getCm1());
        SHA256Compress cm1 = cmCapsule1.getInstance();

        SHA256CompressCapsule cmCapsule2 = new SHA256CompressCapsule();
        cmCapsule2.setContent(zkContract.getCm2());
        SHA256Compress cm2 = cmCapsule2.getInstance();

        //更新已有的witness
        newWitness.forEach(wit -> {
          wit.append(cm1);
          wit.append(cm1);
        });

        ByteString contractId = ByteString.copyFrom(getContractId(zkContract));
        if (foundTx(transaction1, txid)) {
          found = true;

          tree.append(cm1);
          IncrementalMerkleWitnessContainer witness1 = tree.getTreeCapsule().deepCopy()
              .toMerkleTreeContainer().toWitness();
          witness1.getWitnessCapsule().setOutputPoint(contractId, 0);

          witness1.append(cm2);
          tree.append(cm2);

          IncrementalMerkleWitnessContainer witness2 = tree.getTreeCapsule().deepCopy()
              .toMerkleTreeContainer().toWitness();
          witness2.getWitnessCapsule().setOutputPoint(contractId, 1);

          newWitness.add(witness1);
          newWitness.add(witness2);
        } else {
          tree.append(cm1);
          tree.append(cm2);
        }


      }
    }

    if (!found) {
      log.warn("not found valid cm");
      return false;
    }

    if (localBlockNum == currentTxBlockNumber) {
      newWitness.forEach(wit -> {
        dbManager.getMerkleWitnessStore()
            .put(wit.getMerkleWitnessKey(), wit.getWitnessCapsule());
      });
      return true;
    }

    //获取剩余block，并只更新newWitness
    Optional<BlockList> blocksOption = getBlockByLimitNext(currentTxBlockNumber + 1, localBlockNum);

    if (!blocksOption.isPresent()) {
      return false;
    }

    for (Block block1 : blocksOption.get().getBlockList()) {
      for (Transaction transaction1 : block1.getTransactionsList()) {

        Contract contract1 = transaction1.getRawData().getContract(0);
        if (contract1.getType() == ContractType.ZksnarkV0TransferContract) {

          ZksnarkV0TransferContract zkContract = contract1.getParameter()
              .unpack(ZksnarkV0TransferContract.class);

          //getAllWitness，并存入cm（待优化，只更新未使用的witness）
          SHA256CompressCapsule cmCapsule1 = new SHA256CompressCapsule();
          cmCapsule1.setContent(zkContract.getCm1());
          SHA256Compress cm1 = cmCapsule1.getInstance();

          SHA256CompressCapsule cmCapsule2 = new SHA256CompressCapsule();
          cmCapsule2.setContent(zkContract.getCm2());
          SHA256Compress cm2 = cmCapsule2.getInstance();

          newWitness.forEach(wit -> {
            wit.append(cm1);
            wit.append(cm2);
          });

        }
      }
    }

    newWitness.forEach(wit -> {
      dbManager.getMerkleWitnessStore()
          .put(wit.getMerkleWitnessKey(), wit.getWitnessCapsule());
    });

    return true;
  }

  private static byte[] getContractId(ZksnarkV0TransferContract contract) {
    return Sha256Hash.of(contract.toByteArray()).getBytes();
  }

  private static Sha256Hash getTransactionId(Transaction transaction) {
    return Sha256Hash.of(transaction.getRawData().toByteArray());
  }
}
