/* SPDX-License-Identifier: MIT */
pragma solidity ^0.8.21;

import { Address } from "@openzeppelin/contracts/utils/Address.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { Context } from "@openzeppelin/contracts/utils/Context.sol";
import { Nonces } from "@openzeppelin/contracts/utils/Nonces.sol";

contract MetaBloxDIDRegistry is Context, EIP712, Nonces {
    using Address for address;
    using SignatureChecker for address;

    bytes32 private constant _CHANGE_CONTROLLER_TYPEHASH =
        keccak256("ChangeControllerPermit(address did,address newController,uint256 nonce,uint256 deadline)");

    bytes32 private constant _ADD_DELEGATE_PERMIT_TYPEHASH =
        keccak256("AddDelegatePermit(address did,bytes32 delegateType,address delegate,uint256 validity,uint256 nonce,uint256 deadline)");

    bytes32 private constant _REVOKE_DELEGATE_PERMIT_TYPEHASH =
        keccak256("RevokeDelegatePermit(address did,bytes32 delegateType,address delegate,uint256 nonce,uint256 deadline)");

    bytes32 private constant _SET_ATTRIBUTE_PERMIT_TYPEHASH =
        keccak256("SetAttributePermit(address did,address actor,uint256 value,uint256 nonce,uint256 deadline)");

    bytes32 private constant _REVOKE_ATTRIBUTE_PERMIT_TYPEHASH =
        keccak256("RevokeAttributePermit(address did,address actor,uint256 value,uint256 nonce,uint256 deadline)");

    mapping(address => address) private _controllers;
    mapping(address => mapping(bytes32 => mapping(address => uint256))) public delegates;
    mapping(address => uint256) public changed;

    event DIDControllerChanged(address indexed oldController, address newController, uint256 previousChange);

    event DIDDelegateChanged(address indexed did, bytes32 delegateType, address delegate, uint256 validTo, uint256 previousChange);

    event DIDAttributeChanged(address indexed did, bytes32 name, bytes value, uint256 validTo, uint256 previousChange);

    modifier onlyContoller(address did, address actor) {
        require(actor == getController(did), "not_authorized");
        _;
    }

    modifier beforeDeadline(uint256 deadline) {
        require(deadline < block.timestamp, "expired_signature");
        _;
    }

    constructor() EIP712("MetaBloxDIDRegistry", "1") {}

    function changeController(address did, address newController) public {
        _changeController(did, _msgSender(), newController);
    }

    function addDelegate(address did, bytes32 delegateType, address delegate, uint256 validity) public {
        _addDelegate(did, _msgSender(), delegateType, delegate, validity);
    }

    function revokeDelegate(address did, bytes32 delegateType, address delegate) public {
        _revokeDelegate(did, _msgSender(), delegateType, delegate);
    }

    function setAttribute(address did, bytes32 name, bytes memory value, uint256 validity) public {
        _setAttribute(did, _msgSender(), name, value, validity);
    }

    function revokeAttribute(address did, bytes32 name, bytes memory value) public {
        _revokeAttribute(did, _msgSender(), name, value);
    }

    function changeControllerPermit(address did, address newController, uint256 deadline, bytes memory signature) public beforeDeadline(deadline) {
        address signer = getController(did);
        bytes32 structHash = keccak256(abi.encode(_CHANGE_CONTROLLER_TYPEHASH, did, newController, _useNonce(signer), deadline));

        checkSignature(signer, structHash, signature);

        _changeController(did, signer, newController);
    }

    function addDelegatePermit(
        address did,
        bytes32 delegateType,
        address delegate,
        uint256 validity,
        uint256 deadline,
        bytes memory signature
    ) public beforeDeadline(deadline) {
        address signer = getController(did);
        bytes32 structHash = keccak256(abi.encode(_ADD_DELEGATE_PERMIT_TYPEHASH, did, delegateType, delegate, validity, _useNonce(signer), deadline));

        checkSignature(signer, structHash, signature);

        _addDelegate(did, signer, delegateType, delegate, validity);
    }

    function revokeDelegatePermit(
        address did,
        bytes32 delegateType,
        address delegate,
        uint256 deadline,
        bytes memory signature
    ) public beforeDeadline(deadline) {
        address signer = getController(did);
        bytes32 structHash = keccak256(abi.encode(_REVOKE_DELEGATE_PERMIT_TYPEHASH, did, delegateType, delegate, _useNonce(signer), deadline));

        checkSignature(signer, structHash, signature);

        _revokeDelegate(did, signer, delegateType, delegate);
    }

    function setAttributePermit(
        address did,
        bytes32 name,
        bytes memory value,
        uint256 validity,
        uint256 deadline,
        bytes memory signature
    ) public beforeDeadline(deadline) {
        address signer = getController(did);
        bytes32 structHash = keccak256(abi.encode(_SET_ATTRIBUTE_PERMIT_TYPEHASH, did, name, value, validity, _useNonce(signer), deadline));

        checkSignature(signer, structHash, signature);

        _setAttribute(did, signer, name, value, validity);
    }

    function revokeAttributePermit(
        address did,
        bytes32 name,
        bytes memory value,
        uint256 deadline,
        bytes memory signature
    ) public beforeDeadline(deadline) {
        address signer = getController(did);
        bytes32 structHash = keccak256(abi.encode(_REVOKE_ATTRIBUTE_PERMIT_TYPEHASH, did, name, value, _useNonce(signer), deadline));

        checkSignature(signer, structHash, signature);
        _revokeAttribute(did, signer, name, value);
    }

    // readonly functions
    /**
     * @dev Returns the controller of a given did address.
     */
    function getController(address did) public view returns (address) {
        address didController = _controllers[did];
        if (didController != address(0x00)) {
            return didController;
        }
        return did;
    }

    function checkSignature(address signer, bytes32 structHash, bytes memory signature) internal virtual {
        bytes32 hash = _hashTypedDataV4(structHash);
        require(signer.isValidSignatureNow(hash, signature), "invalid_signature");
    }

    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view virtual returns (bytes32) {
        return _domainSeparatorV4();
    }

    function validDelegate(address did, bytes32 delegateType, address delegate) public view returns (bool) {
        uint256 validity = delegates[did][keccak256(abi.encode(delegateType))][delegate];
        return (validity > block.timestamp);
    }

    // internal functions
    function _changeController(address did, address actor, address newController) internal onlyContoller(did, actor) {
        _controllers[did] = newController;
        emit DIDControllerChanged(did, newController, changed[did]);
        changed[did] = block.number;
    }

    function _addDelegate(address did, address actor, bytes32 delegateType, address delegate, uint256 validity) internal onlyContoller(did, actor) {
        delegates[did][keccak256(abi.encode(delegateType))][delegate] = block.timestamp + validity;
        emit DIDDelegateChanged(did, delegateType, delegate, block.timestamp + validity, changed[did]);
        changed[did] = block.number;
    }

    function _setAttribute(address did, address actor, bytes32 name, bytes memory value, uint256 validity) internal onlyContoller(did, actor) {
        emit DIDAttributeChanged(did, name, value, block.timestamp + validity, changed[did]);
        changed[did] = block.number;
    }

    function _revokeAttribute(address did, address actor, bytes32 name, bytes memory value) internal onlyContoller(did, actor) {
        emit DIDAttributeChanged(did, name, value, 0, changed[did]);
        changed[did] = block.number;
    }

    function _revokeDelegate(address did, address actor, bytes32 delegateType, address delegate) internal onlyContoller(did, actor) {
        delegates[did][keccak256(abi.encode(delegateType))][delegate] = block.timestamp;
        emit DIDDelegateChanged(did, delegateType, delegate, block.timestamp, changed[did]);
        changed[did] = block.number;
    }
}
