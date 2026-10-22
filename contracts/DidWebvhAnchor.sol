// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AgentRole} from "../roles/AgentRole.sol";

/**
 * @title DidWebvhAnchor
 * @notice did:webvh 연동 확장 (기존 컨트랙트 무수정).
 *         1) 지갑 ↔ did:webvh 바인딩 기록 (VP 검증 후 agent 가 등록)
 *         2) DID 로그 최신 versionId 앵커링 — 오프체인 로그 롤백(과거 로그 제공) 탐지용.
 *            검증자는 해석한 로그의 versionNumber 가 온체인 값보다 작으면 거부한다.
 */
contract DidWebvhAnchor is AgentRole {
    struct Anchor {
        uint64 versionNumber;
        string versionId;
        uint64 anchoredAt;
    }

    mapping(address => string) private _didOf;
    mapping(bytes32 => address) public walletOfDid; // keccak256(did) => wallet
    mapping(bytes32 => Anchor) private _anchors; // keccak256(did) => latest version

    event DidLinked(address indexed wallet, bytes32 indexed didHash, string did);
    event DidUnlinked(address indexed wallet, bytes32 indexed didHash);
    event VersionAnchored(bytes32 indexed didHash, uint64 versionNumber, string versionId);

    error AlreadyLinked();
    error NotLinked();
    error StaleVersion(uint64 current, uint64 given);
    error ZeroWallet();

    constructor(address initialOwner) AgentRole(initialOwner) {}

    function linkDid(address wallet, string calldata did) external onlyAgent {
        if (wallet == address(0)) revert ZeroWallet();
        bytes32 h = keccak256(bytes(did));
        if (bytes(_didOf[wallet]).length != 0 || walletOfDid[h] != address(0)) revert AlreadyLinked();
        _didOf[wallet] = did;
        walletOfDid[h] = wallet;
        emit DidLinked(wallet, h, did);
    }

    function unlinkDid(address wallet) external onlyAgent {
        string memory did = _didOf[wallet];
        if (bytes(did).length == 0) revert NotLinked();
        bytes32 h = keccak256(bytes(did));
        delete _didOf[wallet];
        delete walletOfDid[h];
        emit DidUnlinked(wallet, h);
    }

    /// @notice 버전은 증가만 허용 (롤백 기록 방지)
    function anchorVersion(string calldata did, uint64 versionNumber, string calldata versionId) external onlyAgent {
        bytes32 h = keccak256(bytes(did));
        uint64 cur = _anchors[h].versionNumber;
        if (versionNumber <= cur) revert StaleVersion(cur, versionNumber);
        // slither-disable-next-line timestamp
        _anchors[h] = Anchor(versionNumber, versionId, uint64(block.timestamp));
        emit VersionAnchored(h, versionNumber, versionId);
    }

    function didOf(address wallet) external view returns (string memory) {
        return _didOf[wallet];
    }

    function anchorOf(string calldata did) external view returns (uint64 versionNumber, string memory versionId, uint64 anchoredAt) {
        Anchor storage a = _anchors[keccak256(bytes(did))];
        return (a.versionNumber, a.versionId, a.anchoredAt);
    }
}
