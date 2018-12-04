package org.tron.core.db.impl;

import com.google.protobuf.ByteString;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.IntStream;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.tron.common.utils.ByteArray;
import org.tron.core.capsule.BytesCapsule;
import org.tron.core.config.Parameter;
import org.tron.core.db.TronStoreWithRevoking;

@Slf4j
@Component
public class DynamicPropertiesStore extends TronStoreWithRevoking<BytesCapsule> {

  private static final byte[] LATEST_WITNESS_BLOCK_NUMBER = "latest_witness_block_number"
      .getBytes();


  @Autowired
  private DynamicPropertiesStore(@Value("properties") String dbName) {
    super(dbName);
  }

  public void saveLatestWitnessBlockNumber(long num) {
    log.debug("LATEST_WITNESS_BLOCK_NUMBER:" + num);
    this.put(LATEST_WITNESS_BLOCK_NUMBER,
        new BytesCapsule(ByteArray.fromLong(num)));
  }

  public long getLatestWitnessBlockNumber() {
    return Optional.ofNullable(getUnchecked(LATEST_WITNESS_BLOCK_NUMBER))
        .map(BytesCapsule::getData)
        .map(ByteArray::toLong)
        .orElseThrow(
            () -> new IllegalArgumentException("not found LATEST_WITNESS_BLOCK_NUMBER"));
  }

}
