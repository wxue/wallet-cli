package org.tron.common.application;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.tron.core.db.Manager;

@Slf4j
@Component
public class ApplicationImpl implements Application {

  @Autowired
  private Manager dbManager;

  @Override
  public void shutdown() {
    log.info("******** begin to shutdown ********");
    synchronized (dbManager) {
      closeAllStore();
    }
    log.info("******** end to shutdown ********");
  }

  @Override
  public Manager getDbManager() {
    return dbManager;
  }

  private void closeAllStore() {
    dbManager.closeAllStore();
  }

}
