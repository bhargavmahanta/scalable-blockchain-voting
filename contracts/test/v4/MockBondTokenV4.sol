// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockBondTokenV4 is ERC20 {
    constructor() ERC20("V4 Test Bond", "V4B") {}

    function mint(address recipient, uint256 amount) external {
        _mint(recipient, amount);
    }
}
