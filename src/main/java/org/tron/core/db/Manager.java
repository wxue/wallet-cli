package org.tron.core.db;

import javax.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.tron.zksnark.merkle.IncrementalMerkleTreeStore;
import org.tron.zksnark.merkle.IncrementalMerkleWitnessStore;
import org.tron.zksnark.merkle.MerkleContainer;

@Slf4j
@Component
public class Manager {

  @Autowired
  @Getter
  private IncrementalMerkleTreeStore merkleTreeStore;
  @Autowired
  @Getter
  private IncrementalMerkleWitnessStore merkleWitnessStore;

  @Getter
  @Setter
  private MerkleContainer merkleContainer;

  @PostConstruct
  public void init() {
    this.setMerkleContainer(merkleContainer.createInstance(this));
  }


  public void closeAllStore() {
    log.info("******** begin to close db ********"); 
    closeOneStore(merkleTreeStore);
    closeOneStore(merkleWitnessStore);
    log.info("******** end to close db ********");
  }

  private void closeOneStore(ITronChainBase database) {
    log.info("******** begin to close " + database.getName() + " ********");
    try {
      database.close();
    } catch (Exception e) {
      log.info("failed to close  " + database.getName() + ". " + e);
    } finally {
      log.info("******** end to close " + database.getName() + " ********");
    }
  }
}
