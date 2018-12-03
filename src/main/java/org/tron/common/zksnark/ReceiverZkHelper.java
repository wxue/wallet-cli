package org.tron.common.zksnark;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.tron.api.GrpcAPI;
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
      return processCase2(txid, localBlockNum, currentTxBlockNumber);
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
    Optional<GrpcAPI.BlockIncrementalMerkleTree> merkleTreeOfBlock = WalletApi
        .getMerkleTreeOfBlock(currentTxBlockNumber - 1);
    if (!merkleTreeOfBlock.isPresent()) {
      log.error("getAndSaveBestMerkleTree error,block not exist");
      return false;
    }
    if (merkleTreeOfBlock.get().getNumber() != currentTxBlockNumber) {
      log.error(
          "getAndSaveBestMerkleTree error,number error,require:" + currentTxBlockNumber + ",found:"
              + merkleTreeOfBlock.get().getNumber());
      return false;
    }

    dbManager.getMerkleContainer().setCurrentMerkle(new IncrementalMerkleTreeCapsule
        (merkleTreeOfBlock.get().getMerkleTree()).toMerkleTreeContainer());
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

    //todo：
    // 1, segmentation query.
    // 2, provide an interface, only return blocks containing anonymous transactions
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
    //Need to update existing witness, tree
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

          //todo: getAllWitness and save cm inot it(to be optimized, only update unused usage)
          SHA256CompressCapsule cmCapsule1 = new SHA256CompressCapsule();
          cmCapsule1.setContent(zkContract.getCm1());
          SHA256Compress cm1 = cmCapsule1.getInstance();

          SHA256CompressCapsule cmCapsule2 = new SHA256CompressCapsule();
          cmCapsule2.setContent(zkContract.getCm2());
          SHA256Compress cm2 = cmCapsule2.getInstance();

          //todo :Witness write can be optimized
          Iterator<Entry<byte[], IncrementalMerkleWitnessCapsule>> iterator = dbManager
              .getMerkleWitnessStore().iterator();
          System.out.println("merkleWitnessStore:" + dbManager.getMerkleWitnessStore().size());
          while (iterator.hasNext()) {
            Entry<byte[], IncrementalMerkleWitnessCapsule> entry = iterator.next();
            IncrementalMerkleWitnessContainer container = entry.getValue()
                .toMerkleWitnessContainer();
            System.out.println("witness before:" + container.getWitnessCapsule().size());
            container.getWitnessCapsule().printSize();
            container.append(cm1);
            container.append(cm2);
            System.out.println("witness after:" + container.getWitnessCapsule().size());
            container.getWitnessCapsule().printSize();
            dbManager.getMerkleWitnessStore()
                .put(entry.getKey(), container.getWitnessCapsule());
          }

          ByteString contractId = ByteString.copyFrom(getContractId(zkContract));
          System.out.println("treeSizeBefore:" + tree.size());
          if (foundTx(transaction1, txid)) {
            System.out.println("foundTx");
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
            System.out.println("witness1 size after:" + witness1.getWitnessCapsule().size());
            System.out.println("witness2 size after:" + witness2.getWitnessCapsule().size());
            dbManager
                .getMerkleWitnessStore()
                .put(witness1.getMerkleWitnessKey(), witness1.getWitnessCapsule());
            dbManager
                .getMerkleWitnessStore()
                .put(witness2.getMerkleWitnessKey(), witness2.getWitnessCapsule());
          } else {
            System.out.println("not foundTx");
            tree.append(cm1);
            tree.append(cm2);
          }

          System.out.println("treeSizeAfter:" + tree.size());
          //Every transaction, save currentTree
          dbManager.getMerkleContainer().setCurrentMerkle(tree);

        }
      }

      //Every block, save currentTree
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

//    System.out.println("txid:" + ByteArray.toHexString(byteString.toByteArray()));
    return ByteArray.toHexString(byteString.toByteArray()).equals(txId);

  }

  public Block getBlock(long blockNum) {
    return WalletApi.getBlock(blockNum);
  }

  protected Optional<IncrementalMerkleTreeContainer> getMerkleTreeBeforeCurrentTxBlock(
      long currentTxBlockNumber) throws ItemNotFoundException {
    byte[] key = dbManager.getTreeBlockIndexStore().get(currentTxBlockNumber - 1);
    if (dbManager.getMerkleTreeStore().contain(key)) {
      IncrementalMerkleTreeContainer tree = dbManager.getMerkleTreeStore()
          .get(key).toMerkleTreeContainer();
      return Optional.of(tree);
    } else {

      Optional<GrpcAPI.BlockIncrementalMerkleTree> merkleTreeOfBlock = WalletApi
          .getMerkleTreeOfBlock(currentTxBlockNumber - 1);
      if (!merkleTreeOfBlock.isPresent()) {
        log.error("getAndSaveBestMerkleTree error,block not exist");
        return Optional.empty();
      }
      if (merkleTreeOfBlock.get().getNumber() != currentTxBlockNumber) {
        log.error(
            "getAndSaveBestMerkleTree error,number error,require:" + currentTxBlockNumber
                + ",found:"
                + merkleTreeOfBlock.get().getNumber());
        return Optional.empty();
      }

      IncrementalMerkleTreeContainer treeContainer = null;
      dbManager.getTreeBlockIndexStore()
          .put(currentTxBlockNumber - 1,
              treeContainer.getMerkleTreeKey());
      dbManager.getMerkleTreeStore()
          .put(treeContainer.getMerkleTreeKey(), treeContainer.getTreeCapsule());
      return Optional.of(treeContainer);
    }
  }

  public boolean processCase2(String txid, long localBlockNum,
      long currentTxBlockNumber) throws InvalidProtocolBufferException, ItemNotFoundException {

    log.info(
        "start to sync block,localBlockNum >= currentTxBlockNumber,localBlockNum:" + localBlockNum
            + ",currentTxBlockNumber:" + currentTxBlockNumber);

    //No need to update existing witness, tree
    //Need to get the tree of the previous block (blockNum to treeKey mapping) and get all anonymous transactions for this block

    //First need to verify that the first block has the witness, and then get the subsequent block accordingly.
    Block block = getBlock(currentTxBlockNumber);
    if (block == null) {
      log.error("getBlock error !!");
      return false;
    }
    Optional<IncrementalMerkleTreeContainer> treeOptional = getMerkleTreeBeforeCurrentTxBlock(
        currentTxBlockNumber);
    if (!treeOptional.isPresent()) {
      return false;
    }

    IncrementalMerkleTreeContainer tree = treeOptional.get();

    System.out.println("treeSize:" + tree.size());

    List<IncrementalMerkleWitnessContainer> newWitness = new ArrayList<>();

    boolean found = false;

    for (Transaction transaction1 : block.getTransactionsList()) {

      Contract contract1 = transaction1.getRawData().getContract(0);
      if (contract1.getType() == ContractType.ZksnarkV0TransferContract) {
        ZksnarkV0TransferContract zkContract = contract1.getParameter()
            .unpack(ZksnarkV0TransferContract.class);

        //todo
        SHA256CompressCapsule cmCapsule1 = new SHA256CompressCapsule();
        cmCapsule1.setContent(zkContract.getCm1());
        SHA256Compress cm1 = cmCapsule1.getInstance();

        SHA256CompressCapsule cmCapsule2 = new SHA256CompressCapsule();
        cmCapsule2.setContent(zkContract.getCm2());
        SHA256Compress cm2 = cmCapsule2.getInstance();

        System.out.println("Update existing witness");

        newWitness.forEach(wit -> {
          System.out.println("witSizeBefore:" + wit.getWitnessCapsule().size());
          wit.getWitnessCapsule().printSize();
          wit.append(cm1);
          wit.append(cm2);

          System.out.println("witSizeAfter:" + wit.getWitnessCapsule().size());
          wit.getWitnessCapsule().printSize();
        });

        ByteString contractId = ByteString.copyFrom(getContractId(zkContract));
        if (foundTx(transaction1, txid)) {
          System.out.println("foundTx");
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

          System.out.println("witness1SizeAfter:" + witness1.getWitnessCapsule().size());
          System.out.println("witness2SizeAfter:" + witness2.getWitnessCapsule().size());
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

    System.out.println("Get the remaining blocks and only update newWitness");
    //Get the remaining blocks and only update newWitness
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

          //todo
          SHA256CompressCapsule cmCapsule1 = new SHA256CompressCapsule();
          cmCapsule1.setContent(zkContract.getCm1());
          SHA256Compress cm1 = cmCapsule1.getInstance();

          SHA256CompressCapsule cmCapsule2 = new SHA256CompressCapsule();
          cmCapsule2.setContent(zkContract.getCm2());
          SHA256Compress cm2 = cmCapsule2.getInstance();

          newWitness.forEach(wit -> {
            System.out.println("witSizeBefore:" + wit.getWitnessCapsule().size());
            wit.getWitnessCapsule().printSize();
            wit.append(cm1);
            wit.append(cm2);
            System.out.println("witSizeAfter:" + wit.getWitnessCapsule().size());
            wit.getWitnessCapsule().printSize();
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
