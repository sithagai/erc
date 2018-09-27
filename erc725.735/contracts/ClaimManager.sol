pragma solidity ^0.4.24;

import "../node_modules/zeppelin-solidity/contracts/ECRecovery.sol";
import "./Pausable.sol";
import "./ERC725.sol";
import "./ERC735.sol";
import "./ERC165Query.sol";



contract ClaimManager is Pausable, ERC725, ERC735 {
    using ECRecovery for bytes32;
    using ERC165Query for address;

    bytes constant internal ETH_PREFIX = "\x19Ethereum Signed Message:\n32";

    struct Claim {
        uint256 topic;
        uint256 scheme;
        address issuer; // msg.sender
        bytes signature; // this.address + topic + data
        bytes data;
        string uri;
    }

    mapping(bytes32 => Claim) internal claims;
    mapping(uint256 => bytes32[]) internal claimsByTopic;
    uint public numClaims;

  /// @dev Requests the ADDITION or the CHANGE of a claim from an issuer.
    ///  Claims can requested to be added by anybody, including the claim holder itself (self issued).
    /// @param _topic Type of claim
    /// @param _scheme Scheme used for the signatures
    /// @param issuer Address of issuer
    /// @param _signature The actual signature
    /// @param _data The data that was signed
    /// @param _uri The location of the claim
    /// @return claimRequestId COULD be send to the approve function, to approve or reject this claim
    function addClaim(
        uint256 _topic,
        uint256 _scheme,
        address issuer,
        bytes _signature,
        bytes _data,
        string _uri
    )
        public
        whenNotPaused
        returns (uint256 claimRequestId)
    {
        // Check signature
        require(_validSignature(_topic, _scheme, issuer, _signature, _data));
        // Check we can perform action
        bool noApproval = _managementOrSelf();

        if (!noApproval) {
            // SHOULD be approved or rejected by n of m approve calls from keys of purpose 1
            claimRequestId = this.execute(address(this), 0, msg.data);
            emit ClaimRequested(claimRequestId, _topic, _scheme, issuer, _signature, _data, _uri);
            return;
        }

        bytes32 claimId = getClaimId(issuer, _topic);
        if (claims[claimId].issuer == address(0)) {
            _addClaim(claimId, _topic, _scheme, issuer, _signature, _data, _uri);
        } else {
            // Existing claim
            Claim storage c = claims[claimId];
            c.scheme = _scheme;
            c.signature = _signature;
            c.data = _data;
            c.uri = _uri;
            // You can't change issuer or topic without affecting the claimId, so we
            // don't need to update those two fields
            emit ClaimChanged(claimId, _topic, _scheme, issuer, _signature, _data, _uri);
        }
    }

    function removeClaim(bytes32 _claimId)
        public
        whenNotPaused
        onlyManagementOrSelfOrIssuer(_claimId)
        returns (bool success)
    {
        Claim memory c = claims[_claimId];
        // Must exist
        require(c.issuer != address(0));
        // Remove from mapping
        delete claims[_claimId];
        // Remove from type array
        bytes32[] storage topics = claimsByTopic[c.topic];
        for (uint i = 0; i < topics.length; i++) {
            if (topics[i] == _claimId) {
                topics[i] = topics[topics.length - 1];
                delete topics[topics.length - 1];
                topics.length--;
                break;
            }
        }
        // Decrement
        numClaims--;
        // Event
        emit ClaimRemoved(_claimId, c.topic, c.scheme, c.issuer, c.signature, c.data, c.uri);
        return true;
    }


    function getClaim(bytes32 _claimId)
        public
        view
        returns (
        uint256 topic,
        uint256 scheme,
        address issuer,
        bytes signature,
        bytes data,
        string uri
        )
    {
        Claim memory c = claims[_claimId];
        require(c.issuer != address(0));
        topic = c.topic;
        scheme = c.scheme;
        issuer = c.issuer;
        signature = c.signature;
        data = c.data;
        uri = c.uri;
    }


    function getClaimIdsByType(uint256 _topic)
        public
        view
        returns(bytes32[] claimIds)
    {
        claimIds = claimsByTopic[_topic];
    }


    function refreshClaim(bytes32 _claimId)
        public
        whenNotPaused
        onlyManagementOrSelfOrIssuer(_claimId)
        returns (bool)
    {
        // Must exist
        Claim memory c = claims[_claimId];
        require(c.issuer != address(0));
        // Check claim is still valid
        if (!_validSignature(c.topic, c.scheme, c.issuer, c.signature, c.data)) {
            // Remove claim
            removeClaim(_claimId);
            return false;
        }

        // Return true if claim is still valid
        return true;
    }


    function getClaimId(address issuer, uint256 topic)
        public
        pure
        returns (bytes32)
    {
        // TODO: Doesn't allow multiple claims from the same issuer with the same type
        // This is particularly inconvenient for self-claims (e.g. self-claim multiple labels)
        return keccak256(abi.encodePacked(issuer, topic));
    }


    function claimToSign(address subject, uint256 topic, bytes data)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(subject, topic, data));
    }

    function getSignatureAddress(bytes32 toSign, bytes signature)
        public
        pure
        returns (address)
    {
        return keccak256(abi.encodePacked(ETH_PREFIX, toSign)).recover(signature);
    }

    function _validSignature(
        uint256 _topic,
        uint256 _scheme,
        address issuer,
        bytes _signature,
        bytes _data
    )
        internal
        view
        returns (bool)
    {
        if (_scheme == ECDSA_SCHEME) {
            address signedBy = getSignatureAddress(claimToSign(address(this), _topic, _data), _signature);
            if (issuer == signedBy) {
                // Issuer signed the signature
                return true;
            } else
            if (issuer == address(this)) {
                return allKeys.find(addrToKey(signedBy), CLAIM_SIGNER_KEY);
            } else
            if (issuer.doesContractImplementInterface(ERC725ID())) {

                return ERC725(issuer).keyHasPurpose(addrToKey(signedBy), CLAIM_SIGNER_KEY);
            }
            // Invalid
            return false;
        } else {
            // Not implemented
            return false;
        }
    }

    /// @dev Modifier that only allows keys of purpose 1, the identity itself, or the issuer or the claim
    modifier onlyManagementOrSelfOrIssuer(bytes32 _claimId) {
        address issuer = claims[_claimId].issuer;
        // Must exist
        require(issuer != 0);

        // Can perform action on claim
        // solhint-disable-next-line no-empty-blocks
        if (_managementOrSelf()) {
            // Valid
        } else
        // solhint-disable-next-line no-empty-blocks
        if (msg.sender == issuer) {
            // MUST only be done by the issuer of the claim
        } else
        if (issuer.doesContractImplementInterface(ERC725ID())) {
            // Issuer is another Identity contract, is this an action key?
            require(ERC725(issuer).keyHasPurpose(addrToKey(msg.sender), ACTION_KEY));
        } else {
            // Invalid! Sender is NOT Management or Self or Issuer
            revert();
        }
        _;
    }


    function _addClaim(
        bytes32 _claimId,
        uint256 _topic,
        uint256 _scheme,
        address issuer,
        bytes _signature,
        bytes _data,
        string _uri
    )
        internal
    {
        // New claim
        claims[_claimId] = Claim(_topic, _scheme, issuer, _signature, _data, _uri);
        claimsByTopic[_topic].push(_claimId);
        numClaims++;
        emit ClaimAdded(_claimId, _topic, _scheme, issuer, _signature, _data, _uri);
    }

    function _updateClaimUri(
        uint256 _topic,
        address issuer,
        string _uri
    )
    internal
    {
        claims[getClaimId(issuer, _topic)].uri = _uri;
    }
}
