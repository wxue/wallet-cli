pragma solidity ^0.4.24;

interface IGOToken {
    function transfer(address receiver, uint256 amount) external returns (bool);

    function balanceOf(address receiver) external view returns (uint256);

    function gameTransferFrom(address _from, address _to, uint256 _value) external returns (bool);
}

contract Basic {
    uint256 constant public precision = 1000000;
    uint256 constant public yi = 100000000;
    uint256 constant public daySec = 24 * 60 * 60;
}

/**
* Math operations with safety checks
*/
contract SafeMath {
    function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a * b;
        _assert(a == 0 || c / a == b);
        return c;
    }

    function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        _assert(b > 0);
        uint256 c = a / b;
        _assert(a == b * c + a % b);
        return c;
    }

    function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
        _assert(b <= a);
        return a - b;
    }

    function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        _assert(c >= a && c >= b);
        return c;
    }

    function _assert(bool assertion) internal pure {
        if (!assertion) {
            revert();
        }
    }
}

contract Ownable {
    address public owner;
    bool public paused = false;
    mapping(address => uint256)  internal  owners;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event  SetOwner(address, uint256);
    constructor() public {
        owner = msg.sender;
        owners[owner] = 1;
    }

    modifier  admin(){
        require(msg.sender == owner);
        _;
    }
    modifier  onlyOwner() {
        bool isInArray = false;
        if (owners[msg.sender] > 0) {
            isInArray = true;
        }
        require(isInArray);
        _;
    }

    function setOwner(address owner_address) public admin {
        owners[owner_address] = 1;
        emit  SetOwner(owner_address, owners[owner_address]);
    }

    //过户
    function transferOwnership(address newOwner) public admin {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    modifier whenNotPaused() {
        require(!paused);
        _;
    }

    modifier whenPaused {
        require(paused);
        _;
    }

    function pause() external admin whenNotPaused {
        paused = true;
    }

    function unPause() public admin whenPaused {
        paused = false;
    }

    function ownerkill() public admin {
        selfdestruct(owner);
    }
}

contract BetToken is Basic, SafeMath {
    string public name = "DiceBet";   //  token name
    string public symbol = "BET";       //  token symbol
    uint8 constant public decimals = 6;        //  token digit
    mapping(address => uint256)  _balanceOf;
    mapping(address => mapping(address => uint256)) public allowed;
    mapping(address => uint256) public freezeBalance;
    mapping(address => uint256) public lockBalance;
    mapping(address => uint256) public unfreezeTime;

    uint256 constant public totalSupply = 200 * yi * precision;
    bool public stopped = false;

    address owner = 0x0;
    mapping(address => uint256) internal gameMaster;
    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert(!stopped);
        _;
    }

    modifier onlyGameMaster{
        require(gameMaster[msg.sender] > 0);
        _;
    }

    constructor () public{
        owner = msg.sender;
        _balanceOf[owner] = totalSupply;
        emit Transfer(0x0, owner, totalSupply);
    }

    function addGameMaster(address addr) public isOwner {
        gameMaster[addr] = 1;
        emit AddGameMaster(addr);
    }

    function removeGameMaster(address addr) public isOwner {
        gameMaster[addr] = 0;
        emit RemoveGameMaster(addr);
    }

    function balanceOf(address addr) public view returns (uint256 balance) {
        balance = _balanceOf[addr];
    }

    function transfer(address to, uint256 value) isRunning public returns (bool success) {
        require(_balanceOf[msg.sender] >= value);
        require(_balanceOf[to] + value >= _balanceOf[to]);
        _balanceOf[msg.sender] = safeSub(_balanceOf[msg.sender], value);
        _balanceOf[to] = safeAdd(_balanceOf[to], value);
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) isRunning public returns (bool success) {
        require(_balanceOf[from] >= value);
        require(_balanceOf[to] + value >= _balanceOf[to]);
        require(allowed[from][msg.sender] >= value);
        _balanceOf[to] = safeAdd(_balanceOf[to], value);
        _balanceOf[from] = safeSub(_balanceOf[from], value);
        allowed[from][msg.sender] = safeSub(allowed[from][msg.sender], value);
        emit Transfer(from, to, value);
        return true;
    }

    function approve(address spender, uint256 value) isRunning public returns (bool success) {
        allowed[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function allowance(address master, address spender) public view returns (uint256 remaining) {
        return allowed[master][spender];
    }

    function gameTransferFrom(address from, address to, uint256 value) isRunning onlyGameMaster public returns (bool success) {
        require(_balanceOf[from] >= value);
        require(_balanceOf[to] + value >= _balanceOf[to]);

        _balanceOf[to] = safeAdd(_balanceOf[to], value);
        _balanceOf[from] = safeSub(_balanceOf[from], value);
        emit GameTransfer(from, to, value);
        return true;
    }

    function stop() isOwner public {
        stopped = true;
    }

    function start() isOwner public {
        stopped = false;
    }

    function setName(string _name) isOwner public {
        name = _name;
    }

    function burn(uint256 value) public {
        require(_balanceOf[msg.sender] >= value);
        _balanceOf[msg.sender] -= value;
        _balanceOf[0x0] += value;
        emit Transfer(msg.sender, 0x0, value);
    }

    function freeze(uint256 value) isRunning public {
        require(_balanceOf[msg.sender] >= value);
        _balanceOf[msg.sender] = safeSub(_balanceOf[msg.sender], value);
        freezeBalance[msg.sender] = safeAdd(freezeBalance[msg.sender], value);
        emit Freeze(msg.sender, value);
    }

    function unfreeze(uint256 value) isRunning public {
        require(freezeBalance[msg.sender] > 0 && freezeBalance[msg.sender] <= value);
        freezeBalance[msg.sender] = safeSub(freezeBalance[msg.sender], value);
        lockBalance[msg.sender] = safeAdd(lockBalance[msg.sender], value);
        unfreezeTime[msg.sender] = now;
        emit Unfreeze(msg.sender, value);
    }

    function unlock(uint256 value) isRunning public {
        require(lockBalance[msg.sender] > 0 && lockBalance[msg.sender] <= value);
        require(now - unfreezeTime[msg.sender] >= daySec);
        lockBalance[msg.sender] = safeSub(lockBalance[msg.sender], value);
        _balanceOf[msg.sender] = safeAdd(_balanceOf[msg.sender], value);
        emit Unlock(msg.sender, value);
    }

    function withdraw(address addr, uint256 amount) public isOwner {
        addr.transfer(amount);
        emit WithDraw(addr, amount);
    }

    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event GameTransfer(address indexed from, address indexed to, uint256 value);
    event AddGameMaster(address addr);
    event RemoveGameMaster(address addr);
    event WithDraw(address _addr, uint256 _amount);
    event Freeze(address addr, uint256 value);
    event Unfreeze(address addr, uint256 value);
    event Unlock(address addr, uint256 value);
}

/**
* TronGame
*/
contract DiceBetGame is Ownable, SafeMath, Basic {
    uint256 _R = 985 * precision; //返现率

    uint256 public minLimit = 10;
    uint256 public maxLimit = 10000;

    uint256 public index = 0;
    uint256 public batchIndex = 0;
    uint256 public payInTotal = 0;
    uint256 public payOutTotal = 0;
    IGOToken public igoToken;
    address public coo = 0x0;

    struct Item {
        address addr;
        uint256 amount;
        uint256 point;
    }

    mapping(uint256 => Item) public items;
    mapping(address => uint256) public payInList;
    mapping(uint256 => uint256) payOutList;
    mapping(uint256 => uint256) randList;

    constructor(address diceTokenAddress) public payable {
        igoToken = IGOToken(diceTokenAddress);
    }
    mapping(address => address) public inviteReward;

    function setCoo(address cooAddress) public onlyOwner {
        coo = cooAddress;
    }

    function setInviteRewards(address from, address to) public onlyOwner {
        inviteReward[to] = from;
        emit SetInviteRewards(from, to);
    }

    function setBetLimit(uint256 _minLimit, uint256 _maxLimit) public onlyOwner {
        minLimit = _minLimit;
        maxLimit = _maxLimit;
        emit SetBetLimit(minLimit, maxLimit);
    }

    function bet(uint256 _point) public whenNotPaused payable returns (uint256) {
        require(msg.value >= minLimit * precision && msg.value <= maxLimit * precision);
        require(_point < 97 && _point > 1);
        index ++;
        Item memory item = Item(msg.sender, msg.value, _point);
        items[index] = item;
        payInTotal += msg.value;
        payInList[msg.sender] = payInList[msg.sender] + msg.value;
        uint256 igoTokenPrice = 0;
        if (payInTotal < 10 * yi * precision) {
            igoTokenPrice = 1;
        } else if (payInTotal < 30 * yi * precision) {
            igoTokenPrice = 2;
        } else if (payInTotal < 70 * yi * precision) {
            igoTokenPrice = 4;
        } else if (payInTotal < 150 * yi * precision) {
            igoTokenPrice = 8;
        } else if (payInTotal < 390 * yi * precision) {
            igoTokenPrice = 12;
        } else if (payInTotal < 710 * yi * precision) {
            igoTokenPrice = 16;
        } else if (payInTotal < 1110 * yi * precision) {
            igoTokenPrice = 20;
        }

        if (igoTokenPrice > 0 && safeDiv(msg.value, igoTokenPrice) > 0) {
            igoToken.transfer(msg.sender, safeDiv(msg.value, igoTokenPrice));
        }
        emit Bet(msg.sender, msg.value);
        return index;
    }

    function rtu(uint256 s) public returns (uint256, address, uint256, uint256, uint256, uint256) {
        require(coo == msg.sender || owner == msg.sender);
        require(batchIndex < index);
        uint256 currIndex = batchIndex + 1;
        uint256 random = s;
        Item memory item = items[currIndex];
        uint256 payOut = 0;
        if (random < item.point) {
            uint256 _P = safeSub(item.point, 1);
            //赔率 * precision = 返现率 * precision / 中奖概率
            uint256 _O = safeDiv(safeDiv(_R, _P), 10);
            uint256 _W = safeDiv(safeMul(item.amount, _O), precision);
            payOut = _W;
            emit UserWin(item.addr, item.amount, item.point, random, _P, _O, _W);
        } else {
            emit UserLose(item.addr, item.amount, item.point, random);
        }
        if (payOut > 0) {
            address(item.addr).transfer(payOut);
            payOutTotal = payOutTotal + payOut;
        }
        payOutList[currIndex] = payOut;
        randList[currIndex] = random;
        batchIndex = currIndex;
        return (batchIndex, item.addr, item.amount, item.point, random, payOut);
    }

    function withdraw(address _address, uint256 _amount) public onlyOwner {
        _address.transfer(_amount);
        emit WithDraw(_address, _amount);
    }

    function check(uint256 _index) public view returns (address, uint256, uint256, uint256) {
        require(coo == msg.sender || owner == msg.sender);
        require(_index <= index);
        Item memory item = items[_index];
        return (item.addr, item.amount, randList[_index], payOutList[_index]);
    }

    function stat() public view returns (uint256, uint256, uint256, uint256) {
        return (index, batchIndex, payInTotal, payOutTotal);
    }

    event SetInviteRewards(address _from, address _to);
    event SetBetLimit(uint256 _minLimit, uint256 _maxLimit);
    event Bet(address _addr, uint256 _amount);
    event WithDraw(address _addr, uint256 _amount);
    event UserWin(address _addr, uint256 _amount, uint256 _point, uint256 _random, uint256 _P, uint256 _O, uint256 _W);
    event UserLose(address _addr, uint256 _amount, uint256 _point, uint256 _random);

}


contract DiceBetGame2 is Ownable, SafeMath, Basic {
    IGOToken public igoToken;
    address public coo = 0x0;
    uint256 _R = 985 * precision; //返现率 * 10000
    //bet limit
    uint256 public minLimit = 10;
    uint256 public maxLimit = 10000;
    uint256 public indexDice = 0;
    uint256 public batchIndexDice = 0;

    struct ItemDice {
        address addr;
        uint256 amount;
        uint256 point;
    }

    mapping(uint256 => ItemDice) itemsDice;
    mapping(address => uint256) payInDiceList;
    mapping(uint256 => uint256) payOutDiceList;
    mapping(uint256 => uint256) randDiceList;
    uint256 public payInDiceTotal = 0;
    uint256 public payOutDiceTotal = 0;

    constructor(address _diceTokenAddress) public {
        igoToken = IGOToken(_diceTokenAddress);
    }

    function setCoo(address cooAddress) public onlyOwner {
        coo = cooAddress;
    }

    function setBetLimit(uint256 _minLimit, uint256 _maxLimit) public onlyOwner {
        minLimit = _minLimit;
        maxLimit = _maxLimit;
        emit SetBetLimit(minLimit, maxLimit);
    }

    function diceBet(uint256 _point, uint256 _msgValue) public whenNotPaused returns (uint256){
        indexDice++;
        require(_msgValue >= minLimit * precision && _msgValue <= maxLimit * precision);
        require(_point < 97 && _point > 1);
        require(igoToken.balanceOf(msg.sender) >= _msgValue);
        require(igoToken.gameTransferFrom(msg.sender, this, _msgValue));

        ItemDice memory itemDice = ItemDice(msg.sender, _msgValue, _point);
        itemsDice[indexDice] = itemDice;
        payInDiceTotal += _msgValue;
        payInDiceList[msg.sender] = payInDiceList[msg.sender] + _msgValue;
        emit Bet(msg.sender, _msgValue);
        return indexDice;
    }

    function diceRtu(uint256 s) public returns (uint256, address, uint256, uint256, uint256, uint256) {
        require(coo == msg.sender || owner == msg.sender);
        require(batchIndexDice < indexDice);
        uint256 currIndex = batchIndexDice + 1;
        uint256 random = s;
        ItemDice memory itemDice = itemsDice[currIndex];
        uint256 payOut = 0;
        if (random < itemDice.point) {
            uint256 _P = safeSub(itemDice.point, 1);
            uint256 _O = safeDiv(safeDiv(_R, _P), 10);
            uint256 _W = safeDiv(safeMul(itemDice.amount, _O), precision);
            payOut = _W;
            emit UserWinDice(itemDice.addr, itemDice.amount, itemDice.point, random, _P, _O, _W);
        } else {
            emit UserLoseDice(itemDice.addr, itemDice.amount, itemDice.point, random);
        }
        if (payOut > 0) {
            igoToken.transfer(itemDice.addr, payOut);
            payOutDiceTotal = payOutDiceTotal + payOut;
        }
        payOutDiceList[currIndex] = payOut;
        randDiceList[currIndex] = random;
        batchIndexDice = currIndex;
        return (batchIndexDice, itemDice.addr, itemDice.amount, itemDice.point, random, payOut);
    }

    function getBalanceOf(address addr) public view returns (uint256){
        uint256 temp = igoToken.balanceOf(addr);
        return temp;
    }

    function withdraw(address addr, uint256 amount) public onlyOwner {
        addr.transfer(amount);
        emit WithDraw(addr, amount);
    }

    function withDrawDice(address addr, uint256 amount) public onlyOwner returns (bool){
        return igoToken.transfer(addr, amount);
    }

    function stat() public view returns (uint256, uint256, uint256, uint256) {
        return (indexDice, batchIndexDice, payInDiceTotal, payOutDiceTotal);
    }

    function check(uint256 index) public view returns (address, uint256, uint256, uint256) {
        require(coo == msg.sender || owner == msg.sender);
        require(index <= indexDice);
        ItemDice memory itemDice = itemsDice[index];
        return (itemDice.addr, itemDice.amount, randDiceList[index], payOutDiceList[index]);
    }

    event WithDraw(address _addr, uint256 _amount);
    event Bet(address _addr, uint256 _amount);
    event SetBetLimit(uint256 _minLimit, uint256 _maxLimit);
    event UserWinDice(address _addr, uint256 _amount, uint256 _point, uint256 _random, uint256 _P, uint256 _O, uint256 _W);
    event UserLoseDice(address _addr, uint256 _amount, uint256 _point, uint256 _random);
}

