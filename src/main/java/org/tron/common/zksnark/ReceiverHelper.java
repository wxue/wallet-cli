package org.tron.common.zksnark;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.tron.api.GrpcAPI.BlockList;
import org.tron.common.zksnark.merkle.IncrementalMerkleTreeContainer;
import org.tron.common.zksnark.merkle.IncrementalMerkleWitnessContainer;
import org.tron.core.capsule.IncrementalMerkleWitnessCapsule;
import org.tron.core.capsule.SHA256CompressCapsule;
import org.tron.core.db.Manager;
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
public class ReceiverHelper {
 
  public static boolean syncBlocksAndUpdateWitness(Manager dbManager,String txid) {

    Optional<TransactionInfo> transactionInfoById = WalletApi.getTransactionInfoById(txid);
    if (!transactionInfoById.isPresent()) {
      System.out.println("TransactionInfo not exists !!");
      return false;
    }
    TransactionInfo transactionInfo = transactionInfoById.get();
    long currentBlockNumber = transactionInfo.getBlockNumber();
    Optional<DynamicProperties> dynamicPropertiesOptional = WalletApi.getDynamicProperties();
    if (!dynamicPropertiesOptional.isPresent()) {
      System.out.println("DynamicProperties not exists !!");
      return false;
    }
    DynamicProperties dynamicProperties = dynamicPropertiesOptional.get();
    long lastSolidityBlockNum = dynamicProperties.getLastSolidityBlockNum();
    if (currentBlockNumber < lastSolidityBlockNum) {
      System.out.println("block is not solidify yet!!");
      return false;
    }
    long localBlockNum = dbManager.getDynamicPropertiesStore()
        .getLatestWitnessBlockNumber();//获取本地块高度，需要存储到dynamicStore
    if (localBlockNum < currentBlockNumber) {
      log.info(
          "start to sync block,localBlockNum < currentBlockNumber,localBlockNum:" + localBlockNum
              + ",currentBlockNumber:"
              + currentBlockNumber);
      //需要更新已有的witness、tree
      Optional<BlockList> blocksOption = WalletApi
          .getBlockByLimitNext(localBlockNum + 1, currentBlockNumber);
      //todo：1、分段查询。2、提供接口，仅返回包含匿名交易的块
      if (!blocksOption.isPresent()) {
        log.error("getBlock error !!");
        return false;
      }

      IncrementalMerkleTreeContainer tree = dbManager.getMerkleContainer()
          .getCurrentMerkle();

      BlockList blockList = blocksOption.get();

      if (blockList.getBlockList().size() != (currentBlockNumber - localBlockNum)) {
        log
            .error("num error,blockList:" + blockList.getBlockList().size() + ",localBlockNum:"
                + localBlockNum + ",currentBlockNumber:" + currentBlockNumber);
      }

      boolean found = false;

      for (Block block : blockList.getBlockList()) {
        for (Transaction transaction1 : block.getTransactionsList()) {

          Contract contract1 = transaction1.getRawData().getContract(0);
          if (contract1.getType() == ContractType.ZksnarkV0TransferContract) {
            try {
              ZksnarkV0TransferContract zkContract = contract1.getParameter()
                  .unpack(ZksnarkV0TransferContract.class);

              //getAllWitness，并存入cm（待优化，只更新未使用的witness）
              SHA256Compress cm1 = new SHA256CompressCapsule(
                  zkContract.getCm1().toByteArray()).getInstance();
              SHA256Compress cm2 = new SHA256CompressCapsule(
                  zkContract.getCm2().toByteArray()).getInstance();

              //witness的写入可以优化
              Iterator<Entry<byte[], IncrementalMerkleWitnessCapsule>> iterator = dbManager
                  .getMerkleWitnessStore().iterator();
              while (iterator.hasNext()) {
                Entry<byte[], IncrementalMerkleWitnessCapsule> entry = iterator.next();
                IncrementalMerkleWitnessContainer container = entry.getValue()
                    .toMerkleWitnessContainer();
                container.append(cm1);
                container.append(cm2);
                dbManager.getMerkleWitnessStore()
                    .put(entry.getKey(), container.getWitnessCapsule());
              }

              //getTree()，并写入cm
              tree.append(cm1);
              //当cm equels 当前cm时，tree "toWitness"，并 witnessList.add(witness);
              //todo，如果cm时需要记录的
              if (false) {
                found = true;
                IncrementalMerkleWitnessContainer witness = tree.toWitness();
                witness.getWitnessCapsule().setOutputPoint();
                dbManager
                    .getMerkleWitnessStore()
                    .put(witness.getMerkleWitnessKey(), witness.getWitnessCapsule());
              }

              tree.append(cm2);
              //todo，如果cm时需要记录的
              if (false) {
                found = true;
                IncrementalMerkleWitnessContainer witness = tree.toWitness();
                witness.getWitnessCapsule().setOutputPoint();
                dbManager
                    .getMerkleWitnessStore()
                    .put(witness.getMerkleWitnessKey(), witness.getWitnessCapsule());
              }
              //每一个交易，存一次currentTree
              dbManager.getMerkleContainer().setCurrentMerkle(tree);
            } catch (Exception ex) {
              log.error("", ex);
            }
          }
        }

        //每一个块，存一次currentTree
        dbManager.getMerkleContainer().saveCurrentMerkleTreeAsBestMerkleTree();
        dbManager.getTreeBlockIndexStore()
            .put(++localBlockNum,
                dbManager.getMerkleContainer().getBestMerkle().getMerkleTreeKey());

      }

      dbManager.getDynamicPropertiesStore().saveLatestWitnessBlockNumber(currentBlockNumber);
      if (!found) {
        log.warn("not found valid cm");
        return false;
      }
    } else {

      log.info(
          "start to sync block,localBlockNum >= currentBlockNumber,localBlockNum:" + localBlockNum
              + ",currentBlockNumber:" + currentBlockNumber);

      //不需要更新已有的witness、tree
      //todo ,单独处理交易对应witness（需要优化）
      //需要拿到前一个块的tree（blockNum到treeKey的映射关系），并获得这个块的所有匿名交易
      try {

        //先需要校验第一个块是否有该witness , 然后依此获得后续块
        Block block = WalletApi.getBlock(currentBlockNumber);
        if (block == null) {
          log.error("getBlock error !!");
          return false;
        }

        byte[] key = dbManager.getTreeBlockIndexStore().get(currentBlockNumber - 1);
        IncrementalMerkleTreeContainer tree = dbManager.getMerkleTreeStore()
            .get(key).toMerkleTreeContainer();

        List<IncrementalMerkleWitnessContainer> newWitness = new ArrayList<>();

        boolean found = false;

        for (Transaction transaction1 : block.getTransactionsList()) {

          Contract contract1 = transaction1.getRawData().getContract(0);
          if (contract1.getType() == ContractType.ZksnarkV0TransferContract) {
            try {
              ZksnarkV0TransferContract zkContract = contract1.getParameter()
                  .unpack(ZksnarkV0TransferContract.class);

              //getAllWitness，并存入cm（待优化，只更新未使用的witness）
              SHA256Compress cm1 = new SHA256CompressCapsule(
                  zkContract.getCm1().toByteArray()).getInstance();
              SHA256Compress cm2 = new SHA256CompressCapsule(
                  zkContract.getCm2().toByteArray()).getInstance();

              tree.append(cm1);
              //更新已有的witness
              newWitness.forEach(wit -> {
                wit.append(cm1);
                wit.append(cm1);
              });

              //todo 判断cm1
              if (false) {
                found = true;
                IncrementalMerkleWitnessContainer witness = tree.toWitness();
                newWitness.add(witness);
              }

              tree.append(cm2);
              if (false) {
                found = true;
                IncrementalMerkleWitnessContainer witness = tree.toWitness();
                newWitness.add(witness);
              }

            } catch (Exception ex) {
              log.error("", ex);
              return false;
            }
          }
        }

        if (!found) {
          log.warn("not found valid cm");
          return false;
        }
        newWitness.forEach(wit -> {
          wit.getWitnessCapsule().setOutputPoint();
        });


        if (localBlockNum == currentBlockNumber) {
          newWitness.forEach(wit -> {
            dbManager.getMerkleWitnessStore()
                .put(wit.getMerkleWitnessKey(), wit.getWitnessCapsule());
          });
          return true;
        }

        //获取剩余block，并只更新newWitness
        Optional<BlockList> blocksOption = WalletApi
            .getBlockByLimitNext(currentBlockNumber + 1, localBlockNum);
        //todo：1、分段查询。2、提供接口，仅返回包含匿名交易的块
        if (!blocksOption.isPresent()) {
          log.error("getBlock error !!");
          return false;
        }

        BlockList blockList = blocksOption.get();

        if (blockList.getBlockList().size() != (localBlockNum - currentBlockNumber)) {
          log
              .error("num error,blockList:" + blockList.getBlockList().size() + ",localBlockNum:"
                  + localBlockNum + ",currentBlockNumber:" + currentBlockNumber);
        }

        for (Block block1 : blockList.getBlockList()) {
          for (Transaction transaction1 : block1.getTransactionsList()) {

            Contract contract1 = transaction1.getRawData().getContract(0);
            if (contract1.getType() == ContractType.ZksnarkV0TransferContract) {
              try {
                ZksnarkV0TransferContract zkContract = contract1.getParameter()
                    .unpack(ZksnarkV0TransferContract.class);

                //getAllWitness，并存入cm（待优化，只更新未使用的witness）
                SHA256Compress cm1 = new SHA256CompressCapsule(
                    zkContract.getCm1().toByteArray()).getInstance();
                SHA256Compress cm2 = new SHA256CompressCapsule(
                    zkContract.getCm2().toByteArray()).getInstance();

                newWitness.forEach(wit -> {
                  wit.append(cm1);
                  wit.append(cm1);
                });
              } catch (Exception ex) {
                log.error("", ex);
              }
            }
          }
        }

        newWitness.forEach(wit -> {
          dbManager.getMerkleWitnessStore()
              .put(wit.getMerkleWitnessKey(), wit.getWitnessCapsule());
        });

      } catch (Exception ex) {
        log.error("", ex);
        return false;
      }


    }

    return true;
  }

}
