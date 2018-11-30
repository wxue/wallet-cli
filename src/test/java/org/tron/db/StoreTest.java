package org.tron.db;

import java.io.File;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.tron.common.application.Application;
import org.tron.common.application.ApplicationFactory;
import org.tron.common.application.TronApplicationContext;
import org.tron.common.utils.FileUtil;
import org.tron.core.config.DefaultConfig;
import org.tron.core.db.Manager;
import org.tron.protos.Contract.SHA256Compress;
import org.tron.core.capsule.IncrementalMerkleTreeCapsule;
import org.tron.core.db.impl.IncrementalMerkleTreeStore;

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

//  @Test
  public void test() {
    IncrementalMerkleTreeStore merkleTreeStore = dbManager.getMerkleTreeStore();
    IncrementalMerkleTreeCapsule capsule = new IncrementalMerkleTreeCapsule();
    capsule.addParents(SHA256Compress.newBuilder().build());
    byte[] key = {0x01}; 
    merkleTreeStore.put(key,capsule);
    IncrementalMerkleTreeCapsule result = merkleTreeStore.get(key);


    String dbName = merkleTreeStore.getDbName();
    System.out.println(dbName);
  }


}
