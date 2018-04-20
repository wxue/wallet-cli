package org.tron.walletserver;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;
import org.tron.api.GrpcAPI;
import org.tron.api.GrpcAPI.AccountList;
import org.tron.api.GrpcAPI.AssetIssueList;
import org.tron.api.GrpcAPI.NodeList;
import org.tron.api.GrpcAPI.WitnessList;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.Hash;
import org.tron.common.crypto.SymmEncoder;
import org.tron.common.utils.*;
import org.tron.core.config.Configuration;
import org.tron.core.config.Parameter.CommonConstant;
import org.tron.protos.Contract;
import org.tron.protos.Contract.AssetIssueContract;
import org.tron.protos.Protocol.*;
import org.tron.protos.Contract.ContractCreationContract.*;

import java.math.BigInteger;
import java.util.*;

class AccountComparator implements Comparator {

  public int compare(Object o1, Object o2) {
    return Long.compare(((Account) o2).getBalance(), ((Account) o1).getBalance());
  }
}

class WitnessComparator implements Comparator {

  public int compare(Object o1, Object o2) {
    return Long.compare(((Witness) o2).getVoteCount(), ((Witness) o1).getVoteCount());
  }
}

public class WalletClient {

  private static final Logger logger = LoggerFactory.getLogger("WalletClient");
  private static final String FilePath = "Wallet";
  private ECKey ecKey = null;
  private boolean loginState = false;

  private static GrpcClient rpcCli = init();
  private static String dbPath;
  private static String txtPath;

//  static {
//    new Timer().schedule(new TimerTask() {
//      @Override
//      public void run() {
//        String fullnode = selectFullNode();
//        if(!"".equals(fullnode)) {
//          rpcCli = new GrpcClient(fullnode);
//        }
//      }
//    }, 3 * 60 * 1000,3 * 60 * 1000);
//  }



  public static GrpcClient init() {
    Config config = Configuration.getByPath("config.conf");
    dbPath = config.getString("CityDb.DbPath");
    txtPath = System.getProperty("user.dir") + '/' + config.getString("CityDb.TxtPath");

    List<String> fullnodelist = config.getStringList("fullnode.ip.list");
    return new GrpcClient(fullnodelist.get(0));
  }

  public static String selectFullNode(){
    Map<String, String> witnessMap = new HashMap<>();
    Config config = Configuration.getByPath("config.conf");
    List list = config.getObjectList("witnesses.witnessList");
    for (int i = 0; i < list.size(); i++) {
      ConfigObject obj = (ConfigObject) list.get(i);
      String ip = obj.get("ip").unwrapped().toString();
      String url = obj.get("url").unwrapped().toString();
      witnessMap.put(url, ip);
    }

    Optional<WitnessList> result = rpcCli.listWitnesses();
    long minMissedNum = 100000000L;
    String minMissedWitness = "";
    if (result.isPresent()) {
      List<Witness> witnessList = result.get().getWitnessesList();
      for (Witness witness : witnessList) {
        String url = witness.getUrl();
        long missedBlocks = witness.getTotalMissed();
        if(missedBlocks < minMissedNum){
          minMissedNum = missedBlocks;
          minMissedWitness = url;
        }
      }
    }
    if(witnessMap.containsKey(minMissedWitness)){
      return witnessMap.get(minMissedWitness);
    }else{
      return "";
    }
  }

  public static String getDbPath() {
    return dbPath;
  }

  public static String getTxtPath() {
    return txtPath;
  }

  /**
   * Creates a new WalletClient with a random ECKey or no ECKey.
   */
  public WalletClient(boolean genEcKey) {
    if (genEcKey) {
      this.ecKey = new ECKey(Utils.getRandom());
    }
  }

  //  Create Wallet with a pritKey
  public WalletClient(String priKey) {
    ECKey temKey = null;
    try {
      BigInteger priK = new BigInteger(priKey, 16);
      temKey = ECKey.fromPrivate(priK);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
    this.ecKey = temKey;
  }

  public boolean login(String password) {
    loginState = checkPassWord(password);
    return loginState;
  }

  public boolean isLoginState() {
    return loginState;
  }

  public void logout() {
    loginState = false;
  }

  /**
   * Get a Wallet from storage
   */
  public static WalletClient GetWalletByStorage(String password) {
    String priKeyEnced = loadPriKey();
    if (priKeyEnced == null) {
      return null;
    }
    //dec priKey
    byte[] priKeyAscEnced = priKeyEnced.getBytes();
    byte[] priKeyHexEnced = Hex.decode(priKeyAscEnced);
    byte[] aesKey = getEncKey(password);
    byte[] priKeyHexPlain = SymmEncoder.AES128EcbDec(priKeyHexEnced, aesKey);
    String priKeyPlain = Hex.toHexString(priKeyHexPlain);

    return new WalletClient(priKeyPlain);
  }

  /**
   * Creates a Wallet with an existing ECKey.
   */

  public WalletClient(final ECKey ecKey) {
    this.ecKey = ecKey;
  }

  public ECKey getEcKey() {
    return ecKey;
  }

  public byte[] getAddress() {
    return ecKey.getAddress();
  }

  public void store(String password) {
    if (ecKey == null || ecKey.getPrivKey() == null) {
      logger.warn("Warning: Store wallet failed, PrivKey is null !!");
      return;
    }
    byte[] pwd = getPassWord(password);
    String pwdAsc = ByteArray.toHexString(pwd);
    byte[] privKeyPlain = ecKey.getPrivKeyBytes();
    System.out.println("privKey:" + ByteArray.toHexString(privKeyPlain));
    //encrypted by password
    byte[] aseKey = getEncKey(password);
    byte[] privKeyEnced = SymmEncoder.AES128EcbEnc(privKeyPlain, aseKey);
    String privKeyStr = ByteArray.toHexString(privKeyEnced);
    byte[] pubKeyBytes = ecKey.getPubKey();
    String pubKeyStr = ByteArray.toHexString(pubKeyBytes);
    // SAVE PASSWORD
    FileUtil.saveData(FilePath, pwdAsc, false);//ofset:0 len:32
    // SAVE PUBKEY
    FileUtil.saveData(FilePath, pubKeyStr, true);//ofset:32 len:130
    // SAVE PRIKEY
    FileUtil.saveData(FilePath, privKeyStr, true);
  }

  public Account queryAccount() {
    byte[] address;
    if (this.ecKey == null) {
      String pubKey = loadPubKey(); //04 PubKey[128]
      if (pubKey == null || "".equals(pubKey)) {
        logger.warn("Warning: QueryAccount failed, no wallet address !!");
        return null;
      }
      byte[] pubKeyAsc = pubKey.getBytes();
      byte[] pubKeyHex = Hex.decode(pubKeyAsc);
      this.ecKey = ECKey.fromPublicOnly(pubKeyHex);
    }
    return queryAccount(getAddress());
  }

  public static Account queryAccount(byte[] address) {
    return rpcCli.queryAccount(address);//call rpc
  }

  private Transaction signTransaction(Transaction transaction) {
    if (this.ecKey == null || this.ecKey.getPrivKey() == null) {
      logger.warn("Warning: Can't sign,there is no private key !!");
      return null;
    }
    transaction = TransactionUtils.setTimestamp(transaction);
    return TransactionUtils.sign(transaction, this.ecKey);
  }

  public boolean sendCoin(byte[] to, long amount) {
    byte[] owner = getAddress();
    Contract.TransferContract contract = createTransferContract(to, owner, amount);
    Transaction transaction = rpcCli.createTransaction(contract);
    if (transaction == null || transaction.getRawData().getContractCount() == 0) {
      return false;
    }
    transaction = signTransaction(transaction);
    return rpcCli.broadcastTransaction(transaction);
  }

  public boolean transferAsset(byte[] to, byte[] assertName, long amount) {
    byte[] owner = getAddress();
    Transaction transaction = createTransferAssetTransaction(to, assertName, owner, amount);
    if (transaction == null || transaction.getRawData().getContractCount() == 0) {
      return false;
    }
    transaction = signTransaction(transaction);
    return rpcCli.broadcastTransaction(transaction);
  }

  public static Transaction createTransferAssetTransaction(byte[] to, byte[] assertName,
      byte[] owner, long amount) {
    Contract.TransferAssetContract contract = createTransferAssetContract(to, assertName, owner,
        amount);
    return rpcCli.createTransferAssetTransaction(contract);
  }

  public boolean participateAssetIssue(byte[] to, byte[] assertName, long amount) {
    byte[] owner = getAddress();
    Transaction transaction = participateAssetIssueTransaction(to, assertName, owner, amount);
    if (transaction == null || transaction.getRawData().getContractCount() == 0) {
      return false;
    }
    transaction = signTransaction(transaction);
    return rpcCli.broadcastTransaction(transaction);
  }

  public static Transaction participateAssetIssueTransaction(byte[] to, byte[] assertName,
      byte[] owner, long amount) {
    Contract.ParticipateAssetIssueContract contract = participateAssetIssueContract(to, assertName,
        owner,
        amount);
    return rpcCli.createParticipateAssetIssueTransaction(contract);
  }


  public boolean createAccount(AccountType accountType, byte[] accountName) {
    Transaction transaction = createAccountTransaction(accountType, accountName, getAddress());
    if (transaction == null || transaction.getRawData().getContractCount() == 0) {
      return false;
    }
    transaction = signTransaction(transaction);
    return rpcCli.broadcastTransaction(transaction);
  }

  public static Transaction
  createAccountTransaction(AccountType accountType, byte[] accountName,
      byte[] address) {
    Contract.AccountCreateContract contract = createAccountCreateContract(accountType, accountName,
        address);
    return rpcCli.createAccount(contract);
  }

  public static boolean broadcastTransaction(byte[] transactionBytes)
      throws InvalidProtocolBufferException {
    Transaction transaction = Transaction.parseFrom(transactionBytes);
    if (false == TransactionUtils.validTransaction(transaction)) {
      return false;
    }
    return rpcCli.broadcastTransaction(transaction);
  }

  public boolean createAssetIssue(Contract.AssetIssueContract contract) {
    Transaction transaction = rpcCli.createAssetIssue(contract);
    if (transaction == null || transaction.getRawData().getContractCount() == 0) {
      return false;
    }
    transaction = signTransaction(transaction);
    return rpcCli.broadcastTransaction(transaction);
  }

  public boolean createWitness(byte[] url) {
    byte[] owner = getAddress();
    Transaction transaction = createWitnessTransaction(owner, url);
    if (transaction == null || transaction.getRawData().getContractCount() == 0) {
      return false;
    }
    transaction = signTransaction(transaction);
    return rpcCli.broadcastTransaction(transaction);
  }

  public static Transaction createWitnessTransaction(byte[] owner, byte[] url) {
    Contract.WitnessCreateContract contract = createWitnessCreateContract(owner, url);
    return rpcCli.createWitness(contract);
  }


  public static Transaction createVoteWitnessTransaction(byte[] owner,
      HashMap<String, String> witness) {
    Contract.VoteWitnessContract contract = createVoteWitnessContract(owner, witness);
    return rpcCli.voteWitnessAccount(contract);
  }

  public static Transaction createAssetIssueTransaction(Contract.AssetIssueContract contract) {
    return rpcCli.createAssetIssue(contract);
  }

  public static Block GetBlock(long blockNum) {
    return rpcCli.getBlock(blockNum);
  }

  public boolean voteWitness(HashMap<String, String> witness) {
    byte[] owner = getAddress();
    Contract.VoteWitnessContract contract = createVoteWitnessContract(owner, witness);
    Transaction transaction = rpcCli.voteWitnessAccount(contract);
    if (transaction == null || transaction.getRawData().getContractCount() == 0) {
      return false;
    }
    transaction = signTransaction(transaction);
    return rpcCli.broadcastTransaction(transaction);
  }

  public static Contract.TransferContract createTransferContract(byte[] to, byte[] owner,
      long amount) {
    Contract.TransferContract.Builder builder = Contract.TransferContract.newBuilder();
    ByteString bsTo = ByteString.copyFrom(to);
    ByteString bsOwner = ByteString.copyFrom(owner);
    builder.setToAddress(bsTo);
    builder.setOwnerAddress(bsOwner);
    builder.setAmount(amount);

    return builder.build();
  }

  public static Contract.TransferAssetContract createTransferAssetContract(byte[] to,
      byte[] assertName, byte[] owner,
      long amount) {
    Contract.TransferAssetContract.Builder builder = Contract.TransferAssetContract.newBuilder();
    ByteString bsTo = ByteString.copyFrom(to);
    ByteString bsName = ByteString.copyFrom(assertName);
    ByteString bsOwner = ByteString.copyFrom(owner);
    builder.setToAddress(bsTo);
    builder.setAssetName(bsName);
    builder.setOwnerAddress(bsOwner);
    builder.setAmount(amount);

    return builder.build();
  }

  public static Contract.ParticipateAssetIssueContract participateAssetIssueContract(byte[] to,
      byte[] assertName, byte[] owner,
      long amount) {
    Contract.ParticipateAssetIssueContract.Builder builder = Contract.ParticipateAssetIssueContract
        .newBuilder();
    ByteString bsTo = ByteString.copyFrom(to);
    ByteString bsName = ByteString.copyFrom(assertName);
    ByteString bsOwner = ByteString.copyFrom(owner);
    builder.setToAddress(bsTo);
    builder.setAssetName(bsName);
    builder.setOwnerAddress(bsOwner);
    builder.setAmount(amount);

    return builder.build();
  }

  public static Transaction createTransaction4Transfer(Contract.TransferContract contract) {
    Transaction transaction = rpcCli.createTransaction(contract);
    return transaction;
  }

  public static Contract.AccountCreateContract createAccountCreateContract(AccountType accountType,
      byte[] accountName, byte[] address) {
    Contract.AccountCreateContract.Builder builder = Contract.AccountCreateContract.newBuilder();
    ByteString bsaAdress = ByteString.copyFrom(address);
    ByteString bsAccountName = ByteString.copyFrom(accountName);
    builder.setType(accountType);
    builder.setAccountName(bsAccountName);
    builder.setOwnerAddress(bsaAdress);

    return builder.build();
  }

  public static Contract.WitnessCreateContract createWitnessCreateContract(byte[] owner,
      byte[] url) {
    Contract.WitnessCreateContract.Builder builder = Contract.WitnessCreateContract.newBuilder();
    builder.setOwnerAddress(ByteString.copyFrom(owner));
    builder.setUrl(ByteString.copyFrom(url));

    return builder.build();
  }

  public static Contract.VoteWitnessContract createVoteWitnessContract(byte[] owner,
      HashMap<String, String> witness) {
    Contract.VoteWitnessContract.Builder builder = Contract.VoteWitnessContract.newBuilder();
    builder.setOwnerAddress(ByteString.copyFrom(owner));
    for (String addressBase58 : witness.keySet()) {
      String value = witness.get(addressBase58);
      long count = Long.parseLong(value);
      Contract.VoteWitnessContract.Vote.Builder voteBuilder = Contract.VoteWitnessContract.Vote
          .newBuilder();
      byte[] address = WalletClient.decodeFromBase58Check(addressBase58);
      if (address == null) {
        continue;
      }
      voteBuilder.setVoteAddress(ByteString.copyFrom(address));
      voteBuilder.setVoteCount(count);
      builder.addVotes(voteBuilder.build());
    }

    return builder.build();
  }

  private static String loadPassword() {
    char[] buf = new char[0x100];
    int len = FileUtil.readData(FilePath, buf);
    if (len != 226) {
      return null;
    }
    return String.valueOf(buf, 0, 32);
  }

  public static String loadPubKey() {
    char[] buf = new char[0x100];
    int len = FileUtil.readData(FilePath, buf);
    if (len != 226) {
      return null;
    }
    return String.valueOf(buf, 32, 130);
  }

  private static String loadPriKey() {
    char[] buf = new char[0x100];
    int len = FileUtil.readData(FilePath, buf);
    if (len != 226) {
      return null;
    }
    return String.valueOf(buf, 162, 64);
  }

  /**
   * Get a Wallet from storage
   */
  public static WalletClient GetWalletByStorageIgnorPrivKey() {
    try {
      String pubKey = loadPubKey(); //04 PubKey[128]
      if (pubKey == null || "".equals(pubKey)) {
        return null;
      }
      byte[] pubKeyAsc = pubKey.getBytes();
      byte[] pubKeyHex = Hex.decode(pubKeyAsc);
      ECKey eccKey = ECKey.fromPublicOnly(pubKeyHex);
      return new WalletClient(eccKey);
    } catch (Exception ex) {
      ex.printStackTrace();
      return null;
    }
  }

  public static String getAddressByStorage() {
    try {
      String pubKey = loadPubKey(); //04 PubKey[128]
      if (pubKey == null || "".equals(pubKey)) {
        return null;
      }
      byte[] pubKeyAsc = pubKey.getBytes();
      byte[] pubKeyHex = Hex.decode(pubKeyAsc);
      ECKey eccKey = ECKey.fromPublicOnly(pubKeyHex);
      return ByteArray.toHexString(eccKey.getAddress());
    } catch (Exception ex) {
      ex.printStackTrace();
      return null;
    }
  }

  public static byte[] getPassWord(String password) {
    if (!passwordValid(password)) {
      return null;
    }
    byte[] pwd;
    pwd = Hash.sha256(password.getBytes());
    pwd = Hash.sha256(pwd);
    pwd = Arrays.copyOfRange(pwd, 0, 16);
    return pwd;
  }

  public static byte[] getEncKey(String password) {
    if (!passwordValid(password)) {
      return null;
    }
    byte[] encKey;
    encKey = Hash.sha256(password.getBytes());
    encKey = Arrays.copyOfRange(encKey, 0, 16);
    return encKey;
  }

  public static boolean checkPassWord(String password) {
    byte[] pwd = getPassWord(password);
    if (pwd == null) {
      return false;
    }
    String pwdAsc = ByteArray.toHexString(pwd);
    String pwdInstore = loadPassword();
    return pwdAsc.equals(pwdInstore);
  }

  public static boolean passwordValid(String password) {
    if (password == null || "".equals(password)) {
      logger.warn("Warning: Password is empty !!");
      return false;
    }
    if (password.length() < 6) {
      logger.warn("Warning: Password is too short !!");
      return false;
    }
    //Other rule;
    return true;
  }

  public static boolean addressValid(byte[] address) {
    if (address == null || address.length == 0) {
      logger.warn("Warning: Address is empty !!");
      return false;
    }
    if (address.length != CommonConstant.ADDRESS_SIZE) {
      logger.warn(
          "Warning: Address length need " + CommonConstant.ADDRESS_SIZE + " but " + address.length
              + " !!");
      return false;
    }
    byte preFixbyte = address[0];
    if (preFixbyte != CommonConstant.ADD_PRE_FIX_BYTE) {
      logger.warn("Warning: Address need prefix with " + CommonConstant.ADD_PRE_FIX_BYTE + " but "
          + preFixbyte + " !!");
      return false;
    }
    //Other rule;
    return true;
  }

  public static String encode58Check(byte[] input) {
    byte[] hash0 = Hash.sha256(input);
    byte[] hash1 = Hash.sha256(hash0);
    byte[] inputCheck = new byte[input.length + 4];
    System.arraycopy(input, 0, inputCheck, 0, input.length);
    System.arraycopy(hash1, 0, inputCheck, input.length, 4);
    return Base58.encode(inputCheck);
  }

  private static byte[] decode58Check(String input) {
    byte[] decodeCheck = Base58.decode(input);
    if (decodeCheck.length <= 4) {
      return null;
    }
    byte[] decodeData = new byte[decodeCheck.length - 4];
    System.arraycopy(decodeCheck, 0, decodeData, 0, decodeData.length);
    byte[] hash0 = Hash.sha256(decodeData);
    byte[] hash1 = Hash.sha256(hash0);
    if (hash1[0] == decodeCheck[decodeData.length] &&
        hash1[1] == decodeCheck[decodeData.length + 1] &&
        hash1[2] == decodeCheck[decodeData.length + 2] &&
        hash1[3] == decodeCheck[decodeData.length + 3]) {
      return decodeData;
    }
    return null;
  }

  public static byte[] decodeFromBase58Check(String addressBase58) {
    if (addressBase58 == null || addressBase58.length() == 0) {
      logger.warn("Warning: Address is empty !!");
      return null;
    }
    if (addressBase58.length() != CommonConstant.BASE58CHECK_ADDRESS_SIZE) {
      logger.warn(
          "Warning: Base58 address length need " + CommonConstant.BASE58CHECK_ADDRESS_SIZE + " but "
              + addressBase58.length()
              + " !!");
      return null;
    }
    byte[] address = decode58Check(addressBase58);
    if (!addressValid(address)) {
      return null;
    }
    return address;
  }

  public static boolean priKeyValid(String priKey) {
    if (priKey == null || "".equals(priKey)) {
      logger.warn("Warning: PrivateKey is empty !!");
      return false;
    }
    if (priKey.length() != 64) {
      logger.warn("Warning: PrivateKey length need 64 but " + priKey.length() + " !!");
      return false;
    }
    //Other rule;
    return true;
  }

  public static Optional<AccountList> listAccounts() {
    Optional<AccountList> result = rpcCli.listAccounts();
    if (result.isPresent()) {
      AccountList accountList = result.get();
      List<Account> list = accountList.getAccountsList();
      List<Account> newList =  new ArrayList();
      newList.addAll(list);
      newList.sort(new AccountComparator());
      AccountList.Builder builder = AccountList.newBuilder();
      newList.forEach(account -> builder.addAccounts(account));
      result = Optional.of(builder.build());
    }
    return result;
  }

  public static Optional<WitnessList> listWitnesses() {
    Optional<WitnessList> result = rpcCli.listWitnesses();
    if (result.isPresent()) {
      WitnessList witnessList = result.get();
      List<Witness> list = witnessList.getWitnessesList();
      List<Witness> newList =  new ArrayList();
      newList.addAll(list);
      newList.sort(new WitnessComparator());
      WitnessList.Builder builder = WitnessList.newBuilder();
      newList.forEach(witness -> builder.addWitnesses(witness));
      result = Optional.of(builder.build());
    }
    return result;
  }

  public static Optional<AssetIssueList> getAssetIssueList() {
    return rpcCli.getAssetIssueList();
  }

  public static Optional<NodeList> listNodes() {
    return rpcCli.listNodes();
  }

  public static Optional<AssetIssueList> getAssetIssueByAccount(byte[] address) {
    return rpcCli.getAssetIssueByAccount(address);
  }

  public static AssetIssueContract getAssetIssueByName(String assetName) {
    return rpcCli.getAssetIssueByName(assetName);
  }

  public static GrpcAPI.NumberMessage getTotalTransaction() {
    return rpcCli.getTotalTransaction();
  }

  /*
   * # Jorge
   */
  public static ABI.Entry.EntryType getEntryType(String type) {
    switch (type) {
      case "constructor": return ABI.Entry.EntryType.Constructor;
      case "function": return ABI.Entry.EntryType.Function;
      case "event": return ABI.Entry.EntryType.Event;
      case "fallback": return ABI.Entry.EntryType.Fallback;
      default: return ABI.Entry.EntryType.UNRECOGNIZED;
    }
  }

  /*
   * # Jorge
   */
  public static ABI.Entry.StateMutabilityType getStateMutability(String stateMutability) {
    switch (stateMutability) {
      case "pure": return ABI.Entry.StateMutabilityType.Pure;
      case "view": return ABI.Entry.StateMutabilityType.View;
      case "nonpayable": return ABI.Entry.StateMutabilityType.Nonpayable;
      case "payable": return ABI.Entry.StateMutabilityType.Payable;
      default: return ABI.Entry.StateMutabilityType.UNRECOGNIZED;
    }
  }

  /*
   * Convert json string to abi # Jorge
   */
  public static Contract.ContractCreationContract.ABI jsonStr2ABI(String jsonStr) {
    if (jsonStr == null) return null;

    JsonParser jsonParser = new JsonParser();
    JsonElement jsonElementRoot = jsonParser.parse(jsonStr);
    JsonArray jsonRoot = jsonElementRoot.getAsJsonArray();
    ABI.Builder abiBuilder = ABI.newBuilder();
    for (int index = 0; index < jsonRoot.size(); index++) {
      JsonElement abiItem = jsonRoot.get(index);
      boolean anonymous = abiItem.getAsJsonObject().get("anonymous") != null?
              abiItem.getAsJsonObject().get("anonymous").getAsBoolean() : false;
      boolean constant = abiItem.getAsJsonObject().get("constant") != null?
              abiItem.getAsJsonObject().get("constant").getAsBoolean() : false;
      String name = abiItem.getAsJsonObject().get("name") != null ?
              abiItem.getAsJsonObject().get("name").getAsString() : null;
      JsonArray inputs = abiItem.getAsJsonObject().get("inputs") != null ?
              abiItem.getAsJsonObject().get("inputs").getAsJsonArray() : null;
      JsonArray outputs = abiItem.getAsJsonObject().get("outputs") != null ?
              abiItem.getAsJsonObject().get("outputs").getAsJsonArray() : null;
      String type = abiItem.getAsJsonObject().get("type") != null ?
              abiItem.getAsJsonObject().get("type").getAsString() : null;
      boolean payable = abiItem.getAsJsonObject().get("payable") != null ?
              abiItem.getAsJsonObject().get("payable").getAsBoolean() : false;
      String stateMutability = abiItem.getAsJsonObject().get("stateMutability") != null ?
              abiItem.getAsJsonObject().get("stateMutability").getAsString() : null;
      if (type == null || inputs == null) {
        logger.error("No type or inputs!");
        return null;
      }

      //System.out.println("[" + anonymous + "| " + name + "|" + inputs.toString() + "|" +stateMutability);
      ABI.Entry.Builder entryBuilder = ABI.Entry.newBuilder();
      entryBuilder.setAnonymous(anonymous);
      entryBuilder.setConstant(constant);
      if (name != null) {
        entryBuilder.setName(ByteString.copyFrom(name.getBytes()));
      }

      /* { inputs : required } */
      for (int j = 0; j < inputs.size(); j++) {
        JsonElement inputItem = inputs.get(j);
        if (inputItem.getAsJsonObject().get("name") == null ||
                inputItem.getAsJsonObject().get("type") == null) {
          logger.error("Input argument invalid due to no name or no type!");
          return null;
        }
        String inputName = inputItem.getAsJsonObject().get("name").getAsString();
        String inputType = inputItem.getAsJsonObject().get("type").getAsString();
        ABI.Entry.Param.Builder paramBuilder = ABI.Entry.Param.newBuilder();
        paramBuilder.setIndexed(false);
        paramBuilder.setName(ByteString.copyFrom(inputName.getBytes()));
        paramBuilder.setType(ByteString.copyFrom(inputType.getBytes()));
        entryBuilder.addInputs(paramBuilder.build());
      }

      /* { outputs : optional } */
      if (outputs != null) {
        for (int k = 0; k < outputs.size(); k++) {
          JsonElement outputItem = outputs.get(k);
          if (outputItem.getAsJsonObject().get("name") == null ||
                  outputItem.getAsJsonObject().get("type") == null) {
            logger.error("Output argument invalid due to no name or no type!");
            return null;
          }
          String outputName = outputItem.getAsJsonObject().get("name").getAsString();
          String outputType = outputItem.getAsJsonObject().get("type").getAsString();
          ABI.Entry.Param.Builder paramBuilder = ABI.Entry.Param.newBuilder();
          paramBuilder.setIndexed(false);
          paramBuilder.setName(ByteString.copyFrom(outputName.getBytes()));
          paramBuilder.setType(ByteString.copyFrom(outputType.getBytes()));
          entryBuilder.addOutputs(paramBuilder.build());
        }
      }

      entryBuilder.setType(getEntryType(type));
      entryBuilder.setPayable(payable);
      if (stateMutability != null) {
        entryBuilder.setStateMutability(getStateMutability(stateMutability));
      }

      abiBuilder.addEntrys(entryBuilder.build());
    }


    return abiBuilder.build();
  }

  /*
   * # Jorge
   */
  public static Contract.ContractCreationContract createContractCreationContract(byte[] address, byte[] contractAddress,
                                                                                 String ABI, String code) {
    Contract.ContractCreationContract.ABI abi = jsonStr2ABI(ABI);
    if (abi == null) {
      logger.error("abi is null");
      return null;
    }

    byte[] codeBytes = Hex.decode(code);
    Contract.ContractCreationContract.Builder builder = Contract.ContractCreationContract.newBuilder();
    builder.setOwnerAddress(ByteString.copyFrom(address));
    builder.setContractAddress(ByteString.copyFrom(contractAddress));
    builder.setAbi(abi);
    builder.setBytecode(ByteString.copyFrom(codeBytes));
    return builder.build();
  }

  /*
   * # Jorge
   */
  public static Contract.ContractCallContract createContractCallContract(byte[] address, byte[] contractAddress,
                                                                         String callValue, String func) {
    return null;
  }

  public static Contract.ContractCreationContract getContract(byte[] address) {
    return rpcCli.getContract(address);
  }

  /*
   * # Jorge
   */
  public boolean createContract(byte[] contractAddress, String ABI, String code) {
    byte[] owner = getAddress();

    Contract.ContractCreationContract contractCreationContract = createContractCreationContract(owner, contractAddress,
            ABI, code);

    Transaction transaction = rpcCli.createContract(contractCreationContract);
    if (transaction == null || transaction.getRawData().getContractCount() == 0) {
      logger.error("RPC create trx failed!");
      return false;
    }

    logger.error("RPC create ok!");

    transaction = signTransaction(transaction);
    return rpcCli.broadcastTransaction(transaction);

  }

  /*
   * # Jorge
   */
  public boolean callContract(String contractAddress, String callValue, String func) {
    byte[] owner = getAddress();
    byte[] contractAddr = Hex.decode(contractAddress);
    Contract.ContractCallContract contractCallContract = createContractCallContract(owner, contractAddr,
            callValue, func);
    Transaction transaction = rpcCli.callContract(contractCallContract);
    if (transaction == null || transaction.getRawData().getContractCount() == 0) {
      return false;
    }

    transaction = signTransaction(transaction);
    return rpcCli.broadcastTransaction(transaction);
  }
}
