package org.tron.core.db.impl;

import com.google.common.collect.Streams;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.tron.core.capsule.IncrementalMerkleWitnessCapsule;
import org.tron.core.db.TronStoreWithRevoking;

@Component
public class IncrementalMerkleWitnessStore extends
    TronStoreWithRevoking<IncrementalMerkleWitnessCapsule> {

  @Autowired
  public IncrementalMerkleWitnessStore(@Value("IncrementalMerkleWitness") String dbName) {
    super(dbName);
  }

  @Override
  public IncrementalMerkleWitnessCapsule get(byte[] key) {
    byte[] value = revokingDB.getUnchecked(key);
    return ArrayUtils.isEmpty(value) ? null : new IncrementalMerkleWitnessCapsule(value);
  }

  public List<IncrementalMerkleWitnessCapsule> getAllWitness() {
    return Streams.stream(iterator())
        .map(Entry::getValue)
        .collect(Collectors.toList());
  }
}