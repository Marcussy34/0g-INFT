# INFT (Intelligent NFTs) --- Deep Technical Walkthrough

> This markdown gives you a detailed, end-to-end view of how **INFTs**
> work in the 0G ecosystem: concepts, components, cryptography,
> lifecycle flows, security model, and minimal integration patterns.

------------------------------------------------------------------------

## TL;DR

**INFTs** are NFTs that *carry* an AI agent (its weights, config,
memory, etc.) as **encrypted metadata**. A new standard, **ERC-7857**,
extends ERC-721 to add: encrypted metadata, secure re-encryption on
transfer (via **TEE** or **ZKP** oracles), proof verification on-chain,
and "authorized usage" so others can run inference without taking
ownership. INFTs plug into **0G Storage** (encrypted persistence), **0G
Chain** (smart contracts, EVM-compatible), **0G Compute** (verifiable
inference), and **0G DA** (data availability).

------------------------------------------------------------------------

## 1) Core Concept

-   **Problem with regular NFTs:** you usually own a *pointer* to model
    metadata; the *intelligence* doesn't move with the token.\
-   **INFT solution:** the AI agent itself is encrypted and bound to the
    token; when the token is transferred, the new owner receives the
    *usable* AI (via re-encryption + proofs).

------------------------------------------------------------------------

## 2) System Architecture (at a glance)

``` mermaid
flowchart LR
  subgraph OnChain[0G Chain (EVM)]
    C[ERC-7857 Contract]
  end
  subgraph OffChain[Off-chain / Oracles]
    O1[TEE Oracle<br/>Re-encrypt + Attest]
    O2[ZKP Prover<br/>Re-encrypt Proof]
  end
  subgraph Storage[0G Storage]
    M[Encrypted AI Metadata<br/>(weights, cfg, memory)]
  end
  U1[Current Owner (PubKey A)]
  U2[New Owner (PubKey B)]
  COMP[0G Compute<br/>(verifiable inference)]
  DA[0G DA]

  U1 -- owns --> C
  C -- URI + hash --> M
  C -- verify proofs --> O1
  C -- verify proofs --> O2
  C -- authorize usage --> COMP
  M -- availability --> DA
  U2 -- sealed key --> C

  O1 -. sealedKey & attestation .-> C
  O2 -. zkProof .-> C

  classDef box fill:#f6f8fa,stroke:#d0d7de,stroke-width:1px,color:#111;
  class C,O1,O2,M,DA,COMP,U1,U2 box;
```

------------------------------------------------------------------------

## 3) Entities & Responsibilities

-   **ERC-7857 Contract (on 0G Chain)**\
    Extends ERC-721 with functions for *transfer-with-re-encryption*,
    *authorized usage*, and (optionally) *clone*. It validates oracle
    proofs and updates the encrypted metadata pointer/hash.

-   **Oracle (TEE or ZKP)**

    -   **TEE path:** decrypts inside an enclave, generates a fresh key,
        re-encrypts for the new owner, emits an **attestation**
        (proof).\
    -   **ZKP path:** verifies that re-encryption was correct *without
        revealing keys*; more compute-heavy; key rotation handled
        client-side.

-   **0G Storage**\
    Durable, decentralized storage for the encrypted metadata blob
    referenced by the token.

-   **0G Compute**\
    Runs *private* inference for owners or authorized executors with a
    return proof (TEE/ZKP) of correct execution.

-   **0G Chain**\
    EVM-compatible L1 optimized for AI throughput/cost; you deploy
    ERC-7857 contracts here.

------------------------------------------------------------------------

## 4) Data Model & Cryptography (practical)

**On-chain (ERC-7857 state):** - `encryptedURI`: a pointer to the
encrypted model/metadata in 0G Storage. - `metadataHash`: integrity hash
of the encrypted payload (and/or structured fields). - authorizations
mapping (per token → executor → permission bytes).

**Off-chain (0G Storage):**\
`{ modelWeights, tokenizer, config, memory/state, adapters, provenance, version }`
--- all **encrypted**.

**Crypto workflow (recommended in docs):** - Symmetric encryption:
**AES-GCM (256-bit)** for payload.\
- Key sealing: RSA-4096 or ECC (e.g., P-384) to wrap the symmetric key
to the owner's public key.\
- Always include authentication tags and verify attestation
freshness/proof validity.

------------------------------------------------------------------------

## 5) Lifecycle Flows

### 5.1 Minting (create → encrypt → store → mint)

``` mermaid
sequenceDiagram
  autonumber
  participant Dev as Dev/Creator
  participant Enc as Encryptor
  participant Store as 0G Storage
  participant C as ERC-7857
  Note over Dev: Train/assemble AI agent
  Dev->>Enc: Produce payload (weights+cfg+state)
  Enc->>Enc: Encrypt payload with AES-GCM; seal key to OwnerPubKey
  Enc->>Store: Upload encrypted blob
  Store-->>Dev: encryptedURI, hash
  Dev->>C: mint(tokenId, encryptedURI, hash, owner)
  C-->>Dev: token minted (INFT)
```

### 5.2 Authorized Usage (AI-as-a-Service without transfer)

``` mermaid
sequenceDiagram
  autonumber
  participant Owner
  participant C as ERC-7857
  participant Exec as Executor (dApp/Service)
  participant Comp as 0G Compute
  Owner->>C: authorizeUsage(tokenId, Exec, permissions)
  Exec->>Comp: runInference(tokenId, input, proofMode)
  Comp-->>Exec: output + verification proof
```

### 5.3 Transfer (TEE path)

``` mermaid
sequenceDiagram
  autonumber
  participant A as Seller (PubKey A)
  participant B as Buyer (PubKey B)
  participant TEE as TEE Oracle
  participant C as ERC-7857
  participant S as 0G Storage

  A->>TEE: encryptedURI_A, sealedKey_A, B.pubkey
  TEE->>TEE: Decrypt inside enclave; re-encrypt payload; seal newKey->B
  TEE-->>A: sealedKey_B, attestation(proof), newEncryptedURI (opt)
  A->>C: transfer(from=A,to=B,tokenId, sealedKey_B, proof)
  C->>C: verify proof (attestation); update hash/URI if provided
  C-->>B: ownership changed
  B->>S: fetch encryptedURI; decrypt using sealedKey_B
```

### 5.4 Transfer (ZKP path)

-   Prover shows *knowledge* of correct re-encryption from old→new key
    without revealing either key or plaintext; contract verifies
    zk-proof before transfer finalizes. (Heavier compute;
    sender/receiver manage key rotation.)

### 5.5 Optional: Clone

-   Some implementations expose a **clone** that creates another token
    with copied encrypted metadata under strict policy;
    proofs/permissions gate this. Use with care.

------------------------------------------------------------------------

## 6) The ERC-7857 Contract Surface (sketch)

``` solidity
interface IERC7857 /* is IERC721 */ {
  function transfer(
    address from,
    address to,
    uint256 tokenId,
    bytes calldata sealedKeyForTo,
    bytes calldata oracleProof
  ) external;

  function clone(
    address to,
    uint256 tokenId,
    bytes calldata sealedKeyForTo,
    bytes calldata oracleProof
  ) external returns (uint256 newTokenId);

  function authorizeUsage(
    uint256 tokenId,
    address executor,
    bytes calldata permissions
  ) external;
}
```

------------------------------------------------------------------------

## 7) Security & Threat Model

-   **Key management:** hardware wallets, key rotation on transfer,
    verify enclave attestations.\
-   **Oracle assumptions:** multi-oracle validation for TEE; circuit
    audits for ZKP.\
-   **Integrity:** store & verify metadataHash; proofs must bind the new
    hash.\
-   **Privacy:** AES-GCM for confidentiality + authenticity.\
-   **Availability:** replicate across 0G Storage + DA layer.

------------------------------------------------------------------------

## 8) Performance, Cost & Deployment Notes

-   **Why 0G Chain:** cheaper/faster than Ethereum L1 for AI-heavy ops.\
-   **Gas profile:** contracts are light; payloads stay off-chain.\
-   **Ecosystem maturity:** ERC-7857 is new (2025), expect tooling
    evolution.

------------------------------------------------------------------------

## 9) Minimal Integration Pattern

**Minting** 1. Train agent.\
2. Encrypt payload; seal key.\
3. Upload to 0G Storage.\
4. Mint ERC-7857 token with URI + hash.

**Authorized Usage** 1. Call authorizeUsage.\
2. Executor runs inference via 0G Compute.\
3. Get output + proof.

**Transfer** 1. Recipient shares pubkey.\
2. Oracle re-encrypts payload.\
3. Contract verifies proof.\
4. New owner decrypts with sealed key.
