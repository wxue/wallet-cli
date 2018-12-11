pragma solidity ^0.4.0;

contract TestLib {
    event ccEvent(bool val);

    // 这是注册 creator 和设置名称的构造函数。
    function TestLib(address caddr) public {
        bool rc = GetCode(caddr).isContract();
        ccEvent(rc);
    }

    // 这是注册 creator 和设置名称的构造函数。
    function func2(address uaddr) public {
        for(int i = 0; i < 10; ++i){
            uaddr.transfer(100);
        }
    }
}

contract GetCode {

    event ttEvent(uint256 val);

    function isContract() public view returns (bool result) {
        address _addr = msg.sender;
        assembly {
            result := extcodesize(_addr)
        }
    }

    function onlyPeople(address _addr) public {
        emit ttEvent(1281);
        // isContract(_addr);
        // require(isContract(_addr) == false);
        // log1(bytes32(0x001), bytes32(_addr));
    }
}