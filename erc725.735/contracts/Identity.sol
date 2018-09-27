pragma solidity ^0.4.24;

import "./Destructible.sol";
import "./ERC735.sol";
import "./KeyGetters.sol";
import "./KeyManager.sol";
import "./MultiSig.sol";
import "./ClaimManager.sol";
import "./Slice.sol";



contract Identity is KeyManager, MultiSig, ClaimManager, Destructible, KeyGetters {
    using Slice for bytes;
    using Slice for string;


    constructor
    (
        bytes32[] _keys,
        uint256[] _purposes,
        uint256 _managementThreshold,
        uint256 _actionThreshold,
        address[] _issuers,
        uint256[] _topics,
        // TODO: Pass bytes[] signatures, bytes[] data and string[] uris once ABIEncoderV2 is out
        bytes _signatures,
        bytes _datas,
        string _uris,
        uint8[] _sizes
    )
    public {
        _validateKeys(_keys, _purposes);
        _validateClaims(_issuers, _topics, _sizes);

        _addKeys(_keys, _purposes, _managementThreshold, _actionThreshold);
        _addClaims(_issuers, _topics, _signatures, _datas, _uris, _sizes);

        // Supports both ERC 725 & 735
        supportedInterfaces[ERC725ID() ^ ERC735ID()] = true;
    }

    function () external payable {
    }



    function _validateKeys
    (
        bytes32[] _keys,
        uint256[] _purposes
    )
    private
    pure
    {
        // Validate keys are sorted and unique
        require(_keys.length == _purposes.length);
        for (uint i = 1; i < _keys.length; i++) {

            bytes32 prevKey = _keys[i - 1];
            require(_keys[i] > prevKey || (_keys[i] == prevKey && _purposes[i] > _purposes[i - 1]));
        }
    }


    function _addKeys
    (
        bytes32[] _keys,
        uint256[] _purposes,
        uint256 _managementThreshold,
        uint256 _actionThreshold
    )
    private
    {
        uint256 actionCount;
        uint256 managementCount;
        if (_keys.length == 0) {
            bytes32 senderKey = addrToKey(msg.sender);
            // Add key that deployed the contract for MANAGEMENT, ACTION, CLAIM
            _addKey(senderKey, MANAGEMENT_KEY, ECDSA_TYPE);
            _addKey(senderKey, ACTION_KEY, ECDSA_TYPE);
            _addKey(senderKey, CLAIM_SIGNER_KEY, ECDSA_TYPE);
            actionCount = 1;
            managementCount = 1;
        } else {
            // Add constructor keys
            for (uint i = 0; i < _keys.length; i++) {
                _addKey(_keys[i], _purposes[i], ECDSA_TYPE);
                if (_purposes[i] == MANAGEMENT_KEY) {
                    managementCount++;
                } else
                if (_purposes[i] == ACTION_KEY) {
                    actionCount++;
                }
            }
        }

        require(_managementThreshold > 0);
        require(_managementThreshold <= managementCount);
        require(_actionThreshold > 0);
        require(_actionThreshold <= actionCount);
        managementThreshold = _managementThreshold;
        actionThreshold = _actionThreshold;
    }


    function _validateClaims
    (
        address[] _issuers,
        uint256[] _topics,
        uint8[] _sizes
    )
    private
    pure
    {
        // Validate claims are sorted and unique
        require(_issuers.length == _topics.length);
        require(3 * _topics.length == _sizes.length);
        for (uint i = 1; i < _issuers.length; i++) {
            // Expect input to be in sorted order, first by issuer, then by topic
            // Sorted order guarantees (issuer, topic) pairs are unique
            address prevIssuer = _issuers[i - 1];
            require(_issuers[i] != prevIssuer || (_issuers[i] == prevIssuer && _topics[i] > _topics[i - 1]));
        }
    }

    function _addClaims
    (
        address[] _issuers,
        uint256[] _topics,
        bytes _signatures,
        bytes _datas,
        string _uris,
        uint8[] _sizes
    )
    private
    {
        // Add constructor claims
        uint[3] memory offset;
        bytes memory signature;
        bytes memory data;
        for (uint i = 0; i < _issuers.length; i++) {
            // Check signature
            signature = _signatures.slice(offset[0], _sizes[3 * i]);
            data = _datas.slice(offset[1], _sizes[3 * i + 1]);
            require(_validSignature(_topics[i], ECDSA_SCHEME, _issuers[i], signature, data));
            // Add claim
            _addClaim(
                getClaimId(_issuers[i], _topics[i]),
                _topics[i],
                ECDSA_SCHEME,
                _issuers[i],
                signature,
                data,
                _uris.slice(offset[2], _sizes[3 * i + 2])
            );
            offset[0] += _sizes[3 * i];
            offset[1] += _sizes[3 * i + 1];
            offset[2] += _sizes[3 * i + 2];
        }
    }
}
