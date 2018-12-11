package org.tron.keystore;

import org.junit.Assert;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;
import org.tron.api.GrpcAPI.TransactionExtention;
import org.tron.common.solc.CompilationResult;
import org.tron.core.exception.CipherException;
import org.tron.core.exception.TronException;
import org.tron.script.AutoCompiler;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SolidityTest extends AutoCompiler {


  @Test
  public void tryTest(){

    try {
      WalletFile user = bankClient.generateAddress(testerPswd);
      cli.loadWalletFile(testerPswd, user);
      dropBalance(user, 1000_000_000);

      CompilationResult compilationResult = doCompile("test01.sol", true);

      CompilationResult.ContractMetadata c1 = compilationResult.getContract("GetCode");
      String contractAddr = deployContract(c1, 1000_000_000);
      logger.info("deploy contract GetCode:", contractAddr);

      TransactionExtention t1 = (TransactionExtention)triggerContract(contractAddr, "isContract()", null, 0);
      logger.info(Hex.toHexString(t1.getConstantResult(0).toByteArray()));
      long l = bytesToLong(t1.getConstantResult(0).toByteArray());
      Assert.assertTrue(l == 0);

    }catch (Exception e) {
      logger.error("test error", e);
    }
  }
}