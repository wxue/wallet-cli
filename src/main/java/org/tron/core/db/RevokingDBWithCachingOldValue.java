package org.tron.core.db;

import com.typesafe.config.Config;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import lombok.Getter;
import org.apache.commons.lang3.ArrayUtils;
import org.tron.common.storage.leveldb.LevelDbDataSourceImpl;
import org.tron.core.config.Configuration;
import org.tron.core.exception.ItemNotFoundException;

public class RevokingDBWithCachingOldValue implements IRevokingDB {

  @Getter
  private LevelDbDataSourceImpl dbSource;

  private String directory;

  public RevokingDBWithCachingOldValue(String dbName) {
    dbSource = new LevelDbDataSourceImpl(Configuration.getOutputDirectoryByDbName(), dbName);
    dbSource.initDB();
  }

  @Override
  public void put(byte[] key, byte[] newValue) {
    if (Objects.isNull(key) || Objects.isNull(newValue)) {
      return;
    }
    //logger.info("Address is {}, " + item.getClass().getSimpleName() + " is {}", key, item);
    byte[] value = dbSource.getData(key);
    dbSource.putData(key, newValue);

  }

  @Override
  public void delete(byte[] key) {
    dbSource.deleteData(key);
  }

  @Override
  public boolean has(byte[] key) {
    return dbSource.getData(key) != null;
  }

  @Override
  public byte[] get(byte[] key) throws ItemNotFoundException {
    byte[] value = dbSource.getData(key);
    if (ArrayUtils.isEmpty(value)) {
      throw new ItemNotFoundException();
    }
    return value;
  }

  @Override
  public byte[] getUnchecked(byte[] key) {
    try {
      return get(key);
    } catch (ItemNotFoundException e) {
      return null;
    }
  }

  @Override
  public void close() {
    dbSource.closeDB();
  }

  @Override
  public void reset() {
    dbSource.resetDb();
  }

  @Override
  public Iterator<Map.Entry<byte[], byte[]>> iterator() {
    return dbSource.iterator();
  }

  @Override
  public Set<byte[]> getlatestValues(long limit) {
    return dbSource.getlatestValues(limit);
  }

  @Override
  public Set<byte[]> getValuesNext(byte[] key, long limit) {
    return dbSource.getValuesNext(key, limit);
  }
}
