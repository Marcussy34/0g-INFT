# 🚀 INFT Starter App Plan (0G‑Aligned)

This plan is updated to strictly follow the **0G INFT (ERC‑7857) spec** and integration guides.

---

## 1. Goal

Build a minimal **INFT-powered DApp** on the **0G Testnet**:

- **App Idea:** AI Quote Generator INFT
- **Flow:** Mint → Authorize usage → Off‑chain inference → Proof/attestation → Verify on‑chain
- **User XP:** Own an NFT that can “speak” (generate quotes) when authorized.

---

## 2. Core Components

### 🔹 On‑Chain (0G Chain / EVM)

- **ERC‑7857 Contract** (extension of ERC‑721)  
  Functions (per spec):
  - `transfer(from,to,tokenId, sealedKey, proof)`
  - `clone(from,to,tokenId, sealedKey, proof)`
  - `authorizeUsage(tokenId, executor, permissions)`
- **Oracle interface** (`IOracle`) for verifying proofs (TEE attestation or ZKP).
- **State stored on chain:**
  - `encryptedURI` → points to encrypted bundle in 0G Storage.
  - `metadataHash` → integrity check of the off‑chain blob.
  - Usage authorizations.

### 🔹 Off‑Chain

- **0G Storage** → encrypted agent artifacts (e.g., JSON with quotes).
- **0G Compute** → runs authorized queries and returns output + proof.
- **Oracles** →
  - TEE oracle (enclave re‑encryption + attestation)
  - ZKP oracle (verifiable re‑encryption without enclave).
- **Node.js/TS Service** → listens for `UsageAuthorized` events, fetches payload from 0G Storage, performs “inference” (random quote), and provides result + oracle proof.

---

## 3. Data Lifecycle

### Minting

1. Developer serializes the “model” (JSON array of quotes).
2. Encrypt with AES‑GCM.
3. Wrap key to owner pubkey.
4. Upload encrypted blob → 0G Storage.
5. Deploy ERC‑7857 on 0G testnet.
6. Call `mint(tokenId, encryptedURI, metadataHash, owner)`.

### Authorized Usage

1. Owner calls `authorizeUsage(tokenId, executor, permissions)` on chain.
2. Executor calls 0G Compute with tokenId + input (e.g., “generate quote”).
3. Compute decrypts blob, runs quote generator, and returns `{output, proof}`.
4. Contract verifies proof via oracle → accepts usage.

### Transfer (TEE path)

1. Recipient provides new pubkey.
2. TEE oracle re‑encrypts payload, outputs `sealedKey + attestation`.
3. Call `transfer(from,to,tokenId, sealedKey, proof)`.
4. Contract verifies via oracle and updates ownership.

### Transfer (ZKP path)

1. Recipient provides new pubkey.
2. ZK prover generates proof: _decrypt with old key → re‑encrypt with new key → hash match_.
3. Call `transfer(...)` with `sealedKey + zkProof`.
4. Contract verifies via oracle and updates ownership.

---

## 4. Example Solidity Skeleton

```solidity
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IOracle {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract INFT is ERC721, ReentrancyGuard {
    struct Metadata {
        string encryptedURI;
        bytes32 metadataHash;
    }

    mapping(uint256 => Metadata) public metadata;
    mapping(uint256 => mapping(address => bytes)) public authorizations;

    address public oracle;

    constructor(address _oracle) ERC721("IntelligentNFT", "INFT") {
        oracle = _oracle;
    }

    function mint(
        uint256 tokenId,
        string memory encryptedURI,
        bytes32 metadataHash,
        address owner
    ) external {
        _safeMint(owner, tokenId);
        metadata[tokenId] = Metadata(encryptedURI, metadataHash);
    }

    function authorizeUsage(uint256 tokenId, address executor, bytes calldata permissions) external {
        require(ownerOf(tokenId) == msg.sender, "Not owner");
        authorizations[tokenId][executor] = permissions;
        emit UsageAuthorized(tokenId, executor);
    }

    function transfer(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata sealedKey,
        bytes calldata proof
    ) external nonReentrant {
        require(ownerOf(tokenId) == from, "Not owner");
        require(IOracle(oracle).verifyProof(proof), "Invalid proof");
        _transfer(from, to, tokenId);
        emit OwnershipTransferred(tokenId, from, to);
    }

    event UsageAuthorized(uint256 tokenId, address executor);
    event OwnershipTransferred(uint256 tokenId, address from, address to);
}
```

---

## 5. Off‑Chain Quote Generator Service (Node.js/TS)

- Listens for `UsageAuthorized` events.
- Fetches encrypted blob from 0G Storage.
- Decrypts locally (or simulates via TEE/ZKP stub).
- Picks random quote.
- Packages `{quote, proof}` → returns to executor.

---

## 6. Required Tools

- **Smart contracts:** Hardhat / Foundry.
- **Storage:** 0G Storage SDK (`npm install @0g/storage`).
- **Compute/Oracles:** 0G Integration SDK.
- **Frontend (optional):** React + Wagmi + RainbowKit.
- **Encryption:** Node.js crypto (AES‑GCM + ECIES).

---

## 7. Networks / Deployment

- **0G Testnet (Galileo or Newton)**
  - RPC: `https://evmrpc-testnet.0g.ai`
  - Chain ID: 16601 (Galileo) / 16600 (Newton).
  - Faucet: [https://faucet.0g.ai](https://faucet.0g.ai).

---

## 8. Step‑by‑Step Walkthrough

1. **Set up Hardhat** → configure 0G testnet RPC + faucet funding.
2. **Deploy INFT.sol** with oracle address stub.
3. **Encrypt JSON of quotes** → upload to 0G Storage SDK.
4. **Mint INFT** with returned URI + hash.
5. **Authorize usage** → watch `UsageAuthorized` in off‑chain service.
6. **Simulate inference** → return random quote + dummy proof.
7. **Integrate oracle** → once TEE/ZK oracle endpoints are public, replace dummy verify with live.

---

## 9. Next Steps for Production

- Swap stub oracle with real 0G TEE/ZKP oracle.
- Implement clone() to allow sub‑licenses.
- Expand JSON payload → actual lightweight ML model.
- Build a UI for interaction.

---

## 🔗 References

- [INFT Overview](https://docs.0g.ai/developer-hub/building-on-0g/inft/inft-overview)
- [ERC‑7857 Spec](https://docs.0g.ai/developer-hub/building-on-0g/inft/erc7857)
- [Integration Guide](https://docs.0g.ai/developer-hub/building-on-0g/inft/integration)
- [0G Testnet Overview](https://docs.0g.ai/developer-hub/network/testnet-overview)
