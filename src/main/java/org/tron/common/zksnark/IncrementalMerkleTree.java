package org.tron.common.zksnark;

import java.util.ArrayList;
import java.util.List;

public class IncrementalMerkleTree {

  public static void main(String[] args) {

    String combined = "1";
    int Depth = 29;
    List<String> parents = new ArrayList<>();
    for (int i = 0; i < Depth; i++) {
      if (i < parents.size()) {
        if (parents.get(i) != null) {
          combined = parents.get(i) +  combined;
          parents.set(i, null);
        } else {
          parents.set(i, combined);
          break;
        }
      } else {
        parents.add(combined);
        break;
      }
    }
    System.out.println(parents);
  }


}
