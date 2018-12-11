package org.tron.walletserver;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.protobuf.ByteString;
import com.typesafe.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;
import org.tron.api.GrpcAPI.AddressPrKeyPairMessage;
import org.tron.api.GrpcAPI.EmptyMessage;
import org.tron.api.GrpcAPI.Return;
import org.tron.api.GrpcAPI.TransactionExtention;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.Sha256Hash;
import org.tron.common.utils.*;
import org.tron.core.config.Configuration;
import org.tron.core.config.Parameter.CommonConstant;
import org.tron.core.exception.CancelException;
import org.tron.core.exception.CipherException;
import org.tron.core.exception.EncodingException;
import org.tron.core.exception.TronException;
import org.tron.keystore.StringUtils;
import org.tron.keystore.Wallet;
import org.tron.keystore.WalletFile;
import org.tron.keystore.WalletUtils;
import org.tron.protos.Contract;
import org.tron.protos.Contract.CreateSmartContract;
import org.tron.protos.Protocol;
import org.tron.protos.Protocol.SmartContract;
import org.tron.protos.Protocol.Account;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Transaction.Result;
import org.tron.protos.Protocol.TransactionInfo;

import java.io.File;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static org.tron.walletserver.WalletApi.generateContractAddress;
import static org.tron.walletserver.WalletApi.jsonStr2ABI;
import static org.tron.walletserver.WalletApi.replaceLibraryAddress;


public class AutoClient {

    private static final Logger logger = LoggerFactory.getLogger("WalletApi");
    private static final String FilePath = "Wallet";
    private ECKey ecKey = null;
    private byte[] address = null;
    private static byte addressPreFixByte = CommonConstant.ADD_PRE_FIX_BYTE_TESTNET;
    private static int rpcVersion = 0;

    private static GrpcClient rpcCli = init();

    public static GrpcClient init() {
        Config config = Configuration.getByPath("config.conf");

        String fullNode = "";
        String solidityNode = "";
        if (config.hasPath("soliditynode.ip.list")) {
            solidityNode = config.getStringList("soliditynode.ip.list").get(0);
        }
        if (config.hasPath("fullnode.ip.list")) {
            fullNode = config.getStringList("fullnode.ip.list").get(0);
        }
        if (config.hasPath("net.type") && "mainnet".equalsIgnoreCase(config.getString("net.type"))) {
            AutoClient.addressPreFixByte = CommonConstant.ADD_PRE_FIX_BYTE_MAINNET;
        } else {
            AutoClient.addressPreFixByte = CommonConstant.ADD_PRE_FIX_BYTE_MAINNET;
        }
        if (config.hasPath("RPC_version")) {
            rpcVersion = config.getInt("RPC_version");
        }
        return new GrpcClient(fullNode, solidityNode);
    }

    public static int getRpcVersion() {
        return rpcVersion;
    }

    public void loadWalletFile(String pswd, WalletFile walletFile) throws CipherException, IOException{
        this.address = decodeFromBase58Check(walletFile.getAddress());
        this.ecKey = Wallet.decrypt(pswd.getBytes(), walletFile);
    }

    public void loadWalletFile(String pswd, int index) throws CipherException, IOException{
        byte[] password = pswd.getBytes();
        File file = new File(FilePath);
        if (!file.exists() || !file.isDirectory()) {
            throw new IOException("No keystore file found, please use registerwallet or importwallet first!");
        }

        File[] wallets = file.listFiles();
        File wallet =  (wallets != null && wallets.length > index)? wallets[index]: null;

        if (wallet == null) {
            logger.warn("wallet is empty");
        }
        WalletFile walletFile = WalletUtils.loadWalletFile(wallet);
        this.address = decodeFromBase58Check(walletFile.getAddress());
        this.ecKey = Wallet.decrypt(password, walletFile);
    }

    public void loadWalletFile(String pswd, String address) throws CipherException, IOException{
        byte[] password = pswd.getBytes();
        File file = new File(FilePath);
        if (!file.exists() || !file.isDirectory()) {
            throw new IOException("No keystore file found, please use registerwallet or importwallet first!");
        }

        File[] wallets = file.listFiles();
        if (wallets == null) {
            throw new IOException("Load wallet file error");
        }
        File wallet = null;
        for (File f : wallets) {
            if (f.getName().toLowerCase().contains(address.toLowerCase())){
                wallet = f;
                break;
            }
        }

        if (wallet == null) {
            throw new IOException("Load wallet [" + address + "] error");
        }
        WalletFile walletFile = WalletUtils.loadWalletFile(wallet);
        this.address = decodeFromBase58Check(walletFile.getAddress());
        this.ecKey = Wallet.decrypt(password, walletFile);
    }

    public static byte[] decodeFromBase58Check(String addressBase58) {
        byte[] address = null;
        byte[] decodeCheck = Base58.decode(addressBase58);
        if (decodeCheck.length > 4) {
            byte[] decodeData = new byte[decodeCheck.length - 4];
            System.arraycopy(decodeCheck, 0, decodeData, 0, decodeData.length);
            byte[] hash1 = Sha256Hash.hashTwice(decodeData);
            if (hash1[0] == decodeCheck[decodeData.length] &&
                    hash1[1] == decodeCheck[decodeData.length + 1] &&
                    hash1[2] == decodeCheck[decodeData.length + 2] &&
                    hash1[3] == decodeCheck[decodeData.length + 3]) {
                address = decodeData;
            }
        }
        return (address != null && address.length == CommonConstant.ADDRESS_SIZE && address[0] == WalletApi.getAddressPreFixByte()) ? address : null;
    }

    private String processTransactionExtention(TransactionExtention transactionExtention){
        if (transactionExtention == null) {
            return null;
        }
        Return ret = transactionExtention.getResult();
        if (!ret.getResult()) {
            logger.warn("Code = " + ret.getCode() + "\n" + ret.getMessage().toStringUtf8());
            return null;
        }
        Transaction transaction = transactionExtention.getTransaction();
        if (transaction == null || transaction.getRawData().getContractCount() == 0) {
            logger.warn("Transaction is empty");
            return null;
        }
        if (transaction.getRawData().getTimestamp() == 0) {
            transaction = TransactionUtils.setTimestamp(transaction);
        }
        transaction = TransactionUtils.sign(transaction, this.ecKey);
        String txId = ByteArray.toHexString(Sha256Hash.hash(transaction.getRawData().toByteArray()));
        logger.info("Receive txid = " + txId);
        return rpcCli.broadcastTransaction(transaction)? txId : null;
    }

    private static CreateSmartContract createContractDeployContract(String contractName,
                                                                   byte[] address,
                                                                   String ABI, String code, long value, long consumeUserResourcePercent, long originEnergyLimit, long tokenValue, String tokenId,
                                                                   String libraryAddressPair) {
        Protocol.SmartContract.ABI abi = jsonStr2ABI(ABI);
        if (abi == null) {
            logger.error("abi is null");
            return null;
        }

        SmartContract.Builder builder = SmartContract.newBuilder();
        builder.setName(contractName);
        builder.setOriginAddress(ByteString.copyFrom(address));
        builder.setAbi(abi);
        builder.setConsumeUserResourcePercent(consumeUserResourcePercent)
                .setOriginEnergyLimit(originEnergyLimit);

        if (value != 0) {

            builder.setCallValue(value);
        }
        byte[] byteCode;
        if (null != libraryAddressPair) {
            byteCode = replaceLibraryAddress(code, libraryAddressPair);
        } else {
            byteCode = Hex.decode(code);
        }

        builder.setBytecode(ByteString.copyFrom(byteCode));
        CreateSmartContract.Builder createSmartContractBuilder = CreateSmartContract.newBuilder();
        createSmartContractBuilder.setOwnerAddress(ByteString.copyFrom(address)).
                setNewContract(builder.build());
        if (tokenId != null && !tokenId.equalsIgnoreCase("") && !tokenId.equalsIgnoreCase("#")){
            createSmartContractBuilder.setCallTokenValue(tokenValue).setTokenId(Long.parseLong(tokenId));
        }
        return createSmartContractBuilder.build();
    }

    public String deployContract(String contractName, String ABI, String code,
                                  long feeLimit, long value, long consumeUserResourcePercent, long originEnergyLimit, long tokenValue, String tokenId, String libraryAddressPair) {

        CreateSmartContract contractDeployContract = createContractDeployContract(contractName, address,
                ABI, code, value, consumeUserResourcePercent, originEnergyLimit, tokenValue, tokenId, libraryAddressPair);

        TransactionExtention transactionExtention = rpcCli.deployContract(contractDeployContract);
        if (transactionExtention == null || !transactionExtention.getResult().getResult()) {
            System.out.println("RPC create trx failed!");
            if (transactionExtention != null) {
                System.out.println("Code = " + transactionExtention.getResult().getCode());
                System.out
                        .println("Message = " + transactionExtention.getResult().getMessage().toStringUtf8());
            }
            return null;
        }

        TransactionExtention.Builder texBuilder = TransactionExtention.newBuilder();
        Transaction.Builder transBuilder = Transaction.newBuilder();
        Transaction.raw.Builder rawBuilder = transactionExtention.getTransaction().getRawData()
                .toBuilder();
        rawBuilder.setFeeLimit(feeLimit);
        transBuilder.setRawData(rawBuilder);
        for (int i = 0; i < transactionExtention.getTransaction().getSignatureCount(); i++) {
            ByteString s = transactionExtention.getTransaction().getSignature(i);
            transBuilder.setSignature(i, s);
        }
        for (int i = 0; i < transactionExtention.getTransaction().getRetCount(); i++) {
            Result r = transactionExtention.getTransaction().getRet(i);
            transBuilder.setRet(i, r);
        }
        texBuilder.setTransaction(transBuilder);
        texBuilder.setResult(transactionExtention.getResult());
        texBuilder.setTxid(transactionExtention.getTxid());
        transactionExtention = texBuilder.build();

        byte[] contractAddress = generateContractAddress(address, transactionExtention.getTransaction());
        System.out.println("Your smart contract address will be: " + WalletApi.encode58Check(contractAddress));
        return processTransactionExtention(transactionExtention);

    }

    public Object triggerContract(String contractAddr, long callValue, byte[] data, long feeLimit, long tokenValue, String tokenId) {

        Contract.TriggerSmartContract.Builder builder = Contract.TriggerSmartContract.newBuilder();
        builder.setOwnerAddress(ByteString.copyFrom(address));
        builder.setContractAddress(ByteString.copyFrom(decodeFromBase58Check(contractAddr)));
        builder.setData(ByteString.copyFrom(data));
        builder.setCallValue(callValue);
        if (tokenId != null && !tokenId.equals("")) {
            builder.setCallTokenValue(tokenValue);
            builder.setTokenId(Long.parseLong(tokenId));
        }
        Contract.TriggerSmartContract triggerContract = builder.build();
        TransactionExtention transactionExtention = rpcCli.triggerContract(triggerContract);
        if (transactionExtention == null || !transactionExtention.getResult().getResult()) {
            logger.warn("RPC create call trx failed! \n" + transactionExtention.getResult().getCode() + "\n" + transactionExtention.getResult().getMessage().toStringUtf8());
            return null;
        }

        Transaction transaction = transactionExtention.getTransaction();
        if (transaction.getRetCount() != 0 &&
                transactionExtention.getConstantResult(0) != null &&
                transactionExtention.getResult() != null) {
            byte[] result = transactionExtention.getConstantResult(0).toByteArray();
            logger.info("message:" + transaction.getRet(0).getRet() + "\n" + ByteArray.toStr(transactionExtention.getResult().getMessage().toByteArray()));
            logger.info("Result:" + Hex.toHexString(result));
            return transactionExtention;
        }

        TransactionExtention.Builder texBuilder = TransactionExtention.newBuilder();
        Transaction.Builder transBuilder = Transaction.newBuilder();
        transBuilder.setRawData(transactionExtention.getTransaction().getRawData().toBuilder().setFeeLimit(feeLimit));
        for (int i = 0; i < transactionExtention.getTransaction().getSignatureCount(); i++) {
            ByteString s = transactionExtention.getTransaction().getSignature(i);
            transBuilder.setSignature(i, s);
        }
        for (int i = 0; i < transactionExtention.getTransaction().getRetCount(); i++) {
            Result r = transactionExtention.getTransaction().getRet(i);
            transBuilder.setRet(i, r);
        }
        texBuilder.setTransaction(transBuilder);
        texBuilder.setResult(transactionExtention.getResult());
        texBuilder.setTxid(transactionExtention.getTxid());
        transactionExtention = texBuilder.build();

        return processTransactionExtention(transactionExtention);
    }

    public String sendCoin(String toAddr, long amount) throws TronException {

        byte[] to = decodeFromBase58Check(toAddr);
        if (to == null){
            throw  new TronException("address empty");
        }

        Contract.TransferContract.Builder builder = Contract.TransferContract.newBuilder();
        ByteString bsTo = ByteString.copyFrom(to);
        ByteString bsOwner = ByteString.copyFrom(address);
        builder.setToAddress(bsTo);
        builder.setOwnerAddress(bsOwner);
        builder.setAmount(amount);
        Contract.TransferContract contract = builder.build();

        TransactionExtention transactionExtention = rpcCli.createTransaction2(contract);
        return processTransactionExtention(transactionExtention);
    }

    public WalletFile generateAddress(String password) throws CipherException {
        EmptyMessage.Builder builder = EmptyMessage.newBuilder();
        AddressPrKeyPairMessage result = rpcCli.generateAddress(builder.build());

        byte[] priKey = StringUtils.hexs2Bytes(result.getPrivateKey().getBytes());
        if (!WalletApi.priKeyValid(priKey)) {
            return null;
        }
        ECKey ecKey = ECKey.fromPrivate(priKey);
//        ECKey ecKey = ECKey.fromPrivate(StringUtils.hexs2Bytes(result.getPrivateKey().getBytes()));
        return Wallet.createStandard(password.getBytes(), ecKey);
    }

    public Account queryAccount() {
        return rpcCli.queryAccount(this.address);//call rpc
    }

    public static Account queryAccount(byte[] address) {
        return rpcCli.queryAccount(address);//call rpc
    }

    public static Optional<TransactionInfo> getTransactionInfoById(String txID) {
        return rpcCli.getTransactionInfoById(txID);
    }

    public static void main(String[] args) {
        AutoClient cli = new AutoClient();
        try {
            cli.loadWalletFile("pswd", "account-address");
            List<Object> params = new LinkedList<Object>(){ {
                add("param-str");
                add(20);
            }};

            byte[] input = AbiUtil.parseMethod("ca(address,uint16)", params, false);
            String txId = (String)cli.triggerContract("contractAddr", 0, input, 1000000000, 0, null);

            Optional<TransactionInfo> result = cli.getTransactionInfoById(txId);
            if (result.isPresent()) {
                TransactionInfo transactionInfo = result.get();
                logger.info(Utils.printTransactionInfo(transactionInfo));
            } else {
                logger.info("getTransactionInfoById " + " failed !!");
            }
        }catch (EncodingException | IOException | CipherException e){
            System.out.println(e);
        }
    }
}
