// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ComplexVault {
    address public owner;
    bool private _locked;
    mapping(address => uint256) public balances;
    uint256 public protocolFee = 25; // 0.25%

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not owner");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "ReentrancyGuard: reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        emit Withdrawal(msg.sender, amount);
    }

    function setProtocolFee(uint256 newFee) external onlyOwner {
        require(newFee <= 100, "Fee too high");
        protocolFee = newFee;
    }

    function getBalance(address account) external view returns (uint256) {
        return balances[account];
    }
}
