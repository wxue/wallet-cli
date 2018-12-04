package org.tron.walletcli;

import com.google.protobuf.ByteString;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tron.api.GrpcAPI;
import org.tron.api.GrpcAPI.AddressPrKeyPairMessage;
import org.tron.api.GrpcAPI.AssetIssueList;
import org.tron.api.GrpcAPI.BlockExtention;
import org.tron.api.GrpcAPI.ExchangeList;
import org.tron.api.GrpcAPI.NodeList;
import org.tron.api.GrpcAPI.ProposalList;
import org.tron.api.GrpcAPI.WitnessList;
import org.tron.common.utils.ByteUtil;
import org.tron.common.utils.ZksnarkUtils;
import org.tron.common.zksnark.ShieldAddressGenerator;
import org.tron.core.db.Manager;
import org.tron.core.exception.CancelException;
import org.tron.core.exception.CipherException;
import org.tron.keystore.StringUtils;
import org.tron.keystore.WalletFile;
import org.tron.protos.Contract;
import org.tron.protos.Contract.ZksnarkV0TransferContract;
import org.tron.protos.Protocol.Account;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.ChainParameters;
import org.tron.protos.Protocol.Exchange;
import org.tron.protos.Protocol.Proposal;
import org.tron.walletserver.ShiledWalletFile;
import org.tron.walletserver.WalletApi;

public class WalletApiWrapper {

  private static final Logger logger = LoggerFactory.getLogger("WalletApiWrapper");
  private WalletApi wallet;


  public String registerWallet(char[] password) throws CipherException, IOException {
    if (!WalletApi.passwordValid(password)) {
      return null;
    }

    byte[] passwd = StringUtils.char2Byte(password);

    wallet = new WalletApi(passwd);

    StringUtils.clear(passwd);

    String keystoreName = wallet.store2Keystore();
    logout();
    return keystoreName;
  }

  public String generateShieldAddress(char[] password) throws CipherException, IOException {
    if (!WalletApi.passwordValid(password)) {
      return null;
    }

    byte[] passwd = StringUtils.char2Byte(password);

    ShieldAddressGenerator shieldAddressGenerator = new ShieldAddressGenerator();

    byte[] privateKey = shieldAddressGenerator.generatePrivateKey();
    byte[] publicKey = shieldAddressGenerator.generatePublicKey(privateKey);

    byte[] privateKeyEnc = shieldAddressGenerator.generatePrivateKeyEnc(privateKey);
    byte[] publicKeyEnc = shieldAddressGenerator.generatePublicKeyEnc(privateKeyEnc);

    byte[] addPrivate = ByteUtil.merge(privateKey, privateKeyEnc);
    byte[] addPublic = ByteUtil.merge(publicKey, publicKeyEnc);

    WalletFile walletFile = org.tron.keystore.Wallet
        .createSheildWallet(passwd, addPublic, addPrivate);
    return WalletApi.storeShiledWallet(walletFile);
  }

  public String importWallet(char[] password, byte[] priKey) throws CipherException, IOException {
    if (!WalletApi.passwordValid(password)) {
      return null;
    }
    if (!WalletApi.priKeyValid(priKey)) {
      return null;
    }

    byte[] passwd = StringUtils.char2Byte(password);

    wallet = new WalletApi(passwd, priKey);
    StringUtils.clear(passwd);

    String keystoreName = wallet.store2Keystore();
    logout();
    return keystoreName;
  }

  public boolean changePassword(char[] oldPassword, char[] newPassword)
      throws IOException, CipherException {
    logout();
    if (!WalletApi.passwordValid(newPassword)) {
      logger.warn("Warning: ChangePassword failed, NewPassword is invalid !!");
      return false;
    }

    byte[] oldPasswd = StringUtils.char2Byte(oldPassword);
    byte[] newPasswd = StringUtils.char2Byte(newPassword);

    boolean result = WalletApi.changeKeystorePassword(oldPasswd, newPasswd);
    StringUtils.clear(oldPasswd);
    StringUtils.clear(newPasswd);

    return result;
  }

  public boolean login(char[] password) throws IOException, CipherException {
    ShiledWalletFile shiled = null;
    if (wallet != null) {
      shiled = wallet.getWalletFile_Shiled();
    }
    wallet = WalletApi.loadWalletFromKeystore();

    byte[] passwd = StringUtils.char2Byte(password);
    wallet.checkPassword(wallet.getWalletFile(), passwd);
    StringUtils.clear(passwd);
    wallet.setLogin();
    wallet.setWalletFile_Shiled(shiled);
    return true;
  }

  public boolean loadShiledWallet(char[] password) throws IOException, CipherException {
    byte[] passwd = StringUtils.char2Byte(password);
    if (wallet == null) {
      wallet = WalletApi.loadShiledWallet(passwd);
    } else {
      WalletFile walletFile = WalletApi.loadShiledWalletFile();
      ShiledWalletFile shiled = new ShiledWalletFile(walletFile, passwd);
      wallet.setWalletFile_Shiled(shiled);
    }

    wallet.checkPassword(wallet.getWalletFile_Shiled().getWalletFile(), passwd);
    StringUtils.clear(passwd);

    return true;
  }

  public void logout() {
    if (wallet != null) {
      wallet.logout();
      wallet = null;
    }
    //Neddn't logout
  }

  //password is current, will be enc by password2.
  public byte[] backupWallet(char[] password) throws IOException, CipherException {
    byte[] passwd = StringUtils.char2Byte(password);

    if (wallet == null || !wallet.isLoginState()) {
      wallet = WalletApi.loadWalletFromKeystore();

      if (wallet == null) {
        StringUtils.clear(passwd);
        System.out.println("Warning: BackupWallet failed, no wallet can be backup !!");
        return null;
      }
    }

    byte[] privateKey = wallet.getPrivateBytes(passwd);
    StringUtils.clear(passwd);

    return privateKey;
  }

  public String getAddress() {
    if (wallet == null || !wallet.isLoginState()) {
      System.out.println("Warning: GetAddress failed,  Please login first !!");
      return null;
    }

    return WalletApi.encode58Check(wallet.getAddress());
  }

  public String getShiledAddress() {
    if (wallet == null || wallet.getWalletFile_Shiled() == null) {
      System.out.println("Warning: GetShiledAddress failed,  Please LoadShiledWallet first !!");
      return null;
    }

    return wallet.getWalletFile_Shiled().getWalletFile().getAddress();
  }

  public Account queryAccount() {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: QueryAccount failed,  Please login first !!");
      return null;
    }

    return wallet.queryAccount();
  }


  public boolean sendCoinShield(long vFromPub, String toPubAddress, long vToPub, String cm1,
      String cm2, String toAddress1, long v1, String toAddress2, long v2,long synBlockNum)
      throws IOException, CipherException, CancelException, SignatureException, InvalidKeyException {
    if (wallet == null) {
      System.out
          .println("Warning: sendCoinShield failed,  Please login or loadShiledWallet first !!");
      return false;
    }
    if ((vFromPub != 0 && !wallet.isLoginState())) {
      System.out.println("Warning: sendCoinShield failed,  Please login first !!");
      return false;
    }
    if (cm1 != null || cm2 != null) {
      if (wallet.getWalletFile_Shiled() == null && wallet.getWalletFile_Shiled_1() == null) {
        System.out
            .println("Warning: sendCoinShield failed,  Please loadShiledWallet first !!");
        return false;
      }
    }
    if ((toPubAddress == null) ^ (vToPub == 0)) {
      System.out.println("Warning: need both toPubAddress is null and vToPub is zero or both not");
      return false;
    }
    if ((toAddress1 == null) ^ (v1 == 0)) {
      System.out.println("Warning: need both toAddress1 is null and v1 is zero or both not");
      return false;
    }
    if ((toAddress2 == null) ^ (v2 == 0)) {
      System.out.println("Warning: need both toAddress2 is null and v2 is zero or both not");
      return false;
    }

    byte[] toPub = null;
    if (toPubAddress != null) {
      toPub = WalletApi.decodeFromBase58Check(toPubAddress);
      if (toPub == null) {
        return false;
      }
    }
    byte[] to1 = null;
    if (toAddress1 != null) {
      to1 = WalletApi.decodeBase58Check(toAddress1);
      if (to1 == null) {
        return false;
      }
    }
    byte[] to2 = null;
    if (toAddress2 != null) {
      to2 = WalletApi.decodeBase58Check(toAddress2);
      if (to2 == null) {
        return false;
      }
    }

    if(synBlockNum<0){
      return false;
    }
    return wallet.sendCoinShield(vFromPub, toPub, vToPub, cm1, cm2, to1, v1, to2, v2,synBlockNum);
  }

  public void listCoin() {
    if (wallet == null || (wallet.getWalletFile_Shiled() == null
        && wallet.getWalletFile_Shiled_1() == null)) {
      System.out
          .println("Warning: listCoin failed,  Please loadShiledWallet first !!");
      return;
    }
    if (wallet.getWalletFile_Shiled() != null) {
      WalletFile walletFile = wallet.getWalletFile_Shiled().getWalletFile();
      System.out.printf("Address is %s :\n", walletFile.getAddress());
      wallet.getWalletFile_Shiled().listCoin();
    }
    if (wallet.getWalletFile_Shiled_1() != null) {
      WalletFile walletFile = wallet.getWalletFile_Shiled_1().getWalletFile();
      System.out.printf("Address is %s :\n", walletFile.getAddress());
      wallet.getWalletFile_Shiled_1().listCoin();
    }
  }


  public boolean sendCoin(String toAddress, long amount)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: SendCoin failed,  Please login first !!");
      return false;
    }
    byte[] to = WalletApi.decodeFromBase58Check(toAddress);
    if (to == null) {
      return false;
    }

    return wallet.sendCoin(to, amount);
  }

  public boolean saveShieldCoin(ZksnarkV0TransferContract contract,String txId )
      throws CipherException {
    if (wallet == null || (wallet.getWalletFile_Shiled() == null
        && wallet.getWalletFile_Shiled_1() == null)) {
      System.out.println("Warning: saveShieldCoin failed, Please load Shiled Wallet first !!");
      return false;
    }
    if (wallet.getWalletFile_Shiled() != null) {
      if (ZksnarkUtils.saveShieldCoin(contract, wallet.getWalletFile_Shiled(),txId)) {
        return true;
      }
    }
    if (wallet.getWalletFile_Shiled_1() != null) {
      if (ZksnarkUtils.saveShieldCoin(contract, wallet.getWalletFile_Shiled_1(),txId)) {
        return true;
      }
    }
    return false;
  }

  public boolean transferAsset(String toAddress, String assertName, long amount)
      throws IOException, CipherException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: TransferAsset failed,  Please login first !!");
      return false;
    }
    byte[] to = WalletApi.decodeFromBase58Check(toAddress);
    if (to == null) {
      return false;
    }

    return wallet.transferAsset(to, assertName.getBytes(), amount);
  }

  public boolean participateAssetIssue(String toAddress, String assertName,
      long amount) throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: TransferAsset failed,  Please login first !!");
      return false;
    }
    byte[] to = WalletApi.decodeFromBase58Check(toAddress);
    if (to == null) {
      return false;
    }

    return wallet.participateAssetIssue(to, assertName.getBytes(), amount);
  }

  public boolean assetIssue(String name, long totalSupply, int trxNum, int icoNum,
      long startTime, long endTime, int voteScore, String description, String url,
      long freeNetLimit, long publicFreeNetLimit, HashMap<String, String> frozenSupply)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: assetIssue failed,  Please login first !!");
      return false;
    }

    Contract.AssetIssueContract.Builder builder = Contract.AssetIssueContract.newBuilder();
    builder.setOwnerAddress(ByteString.copyFrom(wallet.getAddress()));
    builder.setName(ByteString.copyFrom(name.getBytes()));
    if (totalSupply <= 0) {
      return false;
    }
    builder.setTotalSupply(totalSupply);
    if (trxNum <= 0) {
      return false;
    }
    builder.setTrxNum(trxNum);
    if (icoNum <= 0) {
      return false;
    }
    builder.setNum(icoNum);
    long now = System.currentTimeMillis();
    if (startTime <= now) {
      return false;
    }
    if (endTime <= startTime) {
      return false;
    }
    if (freeNetLimit < 0) {
      return false;
    }
    if (publicFreeNetLimit < 0) {
      return false;
    }

    builder.setStartTime(startTime);
    builder.setEndTime(endTime);
    builder.setVoteScore(voteScore);
    builder.setDescription(ByteString.copyFrom(description.getBytes()));
    builder.setUrl(ByteString.copyFrom(url.getBytes()));
    builder.setFreeAssetNetLimit(freeNetLimit);
    builder.setPublicFreeAssetNetLimit(publicFreeNetLimit);

    for (String daysStr : frozenSupply.keySet()) {
      String amountStr = frozenSupply.get(daysStr);
      long amount = Long.parseLong(amountStr);
      long days = Long.parseLong(daysStr);
      Contract.AssetIssueContract.FrozenSupply.Builder frozenSupplyBuilder
          = Contract.AssetIssueContract.FrozenSupply.newBuilder();
      frozenSupplyBuilder.setFrozenAmount(amount);
      frozenSupplyBuilder.setFrozenDays(days);
      builder.addFrozenSupply(frozenSupplyBuilder.build());
    }

    return wallet.createAssetIssue(builder.build());
  }

  public boolean createAccount(String address)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: createAccount failed,  Please login first !!");
      return false;
    }

    byte[] addressBytes = WalletApi.decodeFromBase58Check(address);
    return wallet.createAccount(addressBytes);
  }

  public AddressPrKeyPairMessage generateAddress() {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: createAccount failed,  Please login first !!");
      return null;
    }
    return WalletApi.generateAddress();
  }


  public boolean createWitness(String url) throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: createWitness failed,  Please login first !!");
      return false;
    }

    return wallet.createWitness(url.getBytes());
  }

  public boolean updateWitness(String url) throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: updateWitness failed,  Please login first !!");
      return false;
    }

    return wallet.updateWitness(url.getBytes());
  }

  public Block getBlock(long blockNum) {
    return WalletApi.getBlock(blockNum);
  }

  public long getTransactionCountByBlockNum(long blockNum) {
    return WalletApi.getTransactionCountByBlockNum(blockNum);
  }

  public BlockExtention getBlock2(long blockNum) {
    return WalletApi.getBlock2(blockNum);
  }

  public boolean voteWitness(HashMap<String, String> witness)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: VoteWitness failed,  Please login first !!");
      return false;
    }

    return wallet.voteWitness(witness);
  }

  public Optional<WitnessList> listWitnesses() {
    try {
      return WalletApi.listWitnesses();
    } catch (Exception ex) {
      ex.printStackTrace();
      return Optional.empty();
    }
  }

  public Optional<AssetIssueList> getAssetIssueList() {
    try {
      return WalletApi.getAssetIssueList();
    } catch (Exception ex) {
      ex.printStackTrace();
      return Optional.empty();
    }
  }

  public Optional<AssetIssueList> getAssetIssueList(long offset, long limit) {
    try {
      return WalletApi.getAssetIssueList(offset, limit);
    } catch (Exception ex) {
      ex.printStackTrace();
      return Optional.empty();
    }
  }

  public Optional<ProposalList> getProposalListPaginated(long offset, long limit) {
    try {
      return WalletApi.getProposalListPaginated(offset, limit);
    } catch (Exception ex) {
      ex.printStackTrace();
      return Optional.empty();
    }
  }


  public Optional<ExchangeList> getExchangeListPaginated(long offset, long limit) {
    try {
      return WalletApi.getExchangeListPaginated(offset, limit);
    } catch (Exception ex) {
      ex.printStackTrace();
      return Optional.empty();
    }
  }


  public Optional<NodeList> listNodes() {
    try {
      return WalletApi.listNodes();
    } catch (Exception ex) {
      ex.printStackTrace();
      return Optional.empty();
    }
  }

  public GrpcAPI.NumberMessage getTotalTransaction() {
    return WalletApi.getTotalTransaction();
  }

  public GrpcAPI.NumberMessage getNextMaintenanceTime() {
    return WalletApi.getNextMaintenanceTime();
  }

  public boolean updateAccount(byte[] accountNameBytes)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: updateAccount failed, Please login first !!");
      return false;
    }

    return wallet.updateAccount(accountNameBytes);
  }

  public boolean setAccountId(byte[] accountIdBytes)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: setAccount failed, Please login first !!");
      return false;
    }

    return wallet.setAccountId(accountIdBytes);
  }


  public boolean updateAsset(byte[] description, byte[] url, long newLimit,
      long newPublicLimit) throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: updateAsset failed, Please login first !!");
      return false;
    }

    return wallet.updateAsset(description, url, newLimit, newPublicLimit);
  }

  public boolean freezeBalance(long frozen_balance, long frozen_duration, int resourceCode,
      String receiverAddress)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: freezeBalance failed, Please login first !!");
      return false;
    }

    return wallet.freezeBalance(frozen_balance, frozen_duration, resourceCode, receiverAddress);
  }

  public boolean buyStorage(long quantity)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: buyStorage failed, Please login first !!");
      return false;
    }

    return wallet.buyStorage(quantity);
  }

  public boolean buyStorageBytes(long bytes)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: buyStorageBytes failed, Please login first !!");
      return false;
    }

    return wallet.buyStorageBytes(bytes);
  }

  public boolean sellStorage(long storageBytes)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: sellStorage failed, Please login first !!");
      return false;
    }

    return wallet.sellStorage(storageBytes);
  }


  public boolean unfreezeBalance(int resourceCode)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: unfreezeBalance failed, Please login first !!");
      return false;
    }

    return wallet.unfreezeBalance(resourceCode);
  }


  public boolean unfreezeAsset() throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: unfreezeAsset failed, Please login first !!");
      return false;
    }

    return wallet.unfreezeAsset();
  }

  public boolean withdrawBalance() throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: withdrawBalance failed, Please login first !!");
      return false;
    }

    return wallet.withdrawBalance();
  }

  public boolean createProposal(HashMap<Long, Long> parametersMap)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: createProposal failed, Please login first !!");
      return false;
    }

    return wallet.createProposal(parametersMap);
  }


  public Optional<ProposalList> getProposalsList() {
    try {
      return WalletApi.listProposals();
    } catch (Exception ex) {
      ex.printStackTrace();
      return Optional.empty();
    }
  }

  public Optional<Proposal> getProposals(String id) {
    try {
      return WalletApi.getProposal(id);
    } catch (Exception ex) {
      ex.printStackTrace();
      return Optional.empty();
    }
  }

  public Optional<ExchangeList> getExchangeList() {
    try {
      return WalletApi.listExchanges();
    } catch (Exception ex) {
      ex.printStackTrace();
      return Optional.empty();
    }
  }

  public Optional<Exchange> getExchange(String id) {
    try {
      return WalletApi.getExchange(id);
    } catch (Exception ex) {
      ex.printStackTrace();
      return Optional.empty();
    }
  }

  public Optional<ChainParameters> getChainParameters() {
    try {
      return WalletApi.getChainParameters();
    } catch (Exception ex) {
      ex.printStackTrace();
      return Optional.empty();
    }
  }


  public boolean approveProposal(long id, boolean is_add_approval)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: approveProposal failed, Please login first !!");
      return false;
    }

    return wallet.approveProposal(id, is_add_approval);
  }

  public boolean deleteProposal(long id)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: deleteProposal failed, Please login first !!");
      return false;
    }

    return wallet.deleteProposal(id);
  }

  public boolean exchangeCreate(byte[] firstTokenId, long firstTokenBalance,
      byte[] secondTokenId, long secondTokenBalance)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: exchangeCreate failed, Please login first !!");
      return false;
    }

    return wallet.exchangeCreate(firstTokenId, firstTokenBalance,
        secondTokenId, secondTokenBalance);
  }

  public boolean exchangeInject(long exchangeId, byte[] tokenId, long quant)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: exchangeInject failed, Please login first !!");
      return false;
    }

    return wallet.exchangeInject(exchangeId, tokenId, quant);
  }

  public boolean exchangeWithdraw(long exchangeId, byte[] tokenId, long quant)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: exchangeWithdraw failed, Please login first !!");
      return false;
    }

    return wallet.exchangeWithdraw(exchangeId, tokenId, quant);
  }

  public boolean exchangeTransaction(long exchangeId, byte[] tokenId, long quant, long expected)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: exchangeTransaction failed, Please login first !!");
      return false;
    }

    return wallet.exchangeTransaction(exchangeId, tokenId, quant, expected);
  }

  public boolean updateSetting(byte[] contractAddress, long consumeUserResourcePercent)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: updateSetting failed,  Please login first !!");
      return false;
    }
    return wallet.updateSetting(contractAddress, consumeUserResourcePercent);

  }

  public boolean deployContract(String name, String abiStr, String codeStr,
      long feeLimit, long value, long consumeUserResourcePercent, String libraryAddressPair)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: createContract failed,  Please login first !!");
      return false;
    }
    return wallet
        .deployContract(name, abiStr, codeStr, feeLimit, value, consumeUserResourcePercent,
            libraryAddressPair);
  }

  public boolean callContract(byte[] contractAddress, long callValue, byte[] data, long feeLimit)
      throws CipherException, IOException, CancelException {
    if (wallet == null || !wallet.isLoginState()) {
      logger.warn("Warning: callContract failed,  Please login first !!");
      return false;
    }

    return wallet.triggerContract(contractAddress, callValue, data, feeLimit);
  }

}
