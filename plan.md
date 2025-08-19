# Plan.md — AI Quote Generator INFT (0G Testnet, end‑to‑end)

This plan lets you build a **fully working INFT demo** on the **0G testnet** for free: mint ↔ authorizeUsage ↔ off‑chain inference ↔ (mock) proof ↔ verify. It assumes basic Web3 + Node/Python familiarity.

---

## 0) What you’ll build (quick picture)

- **ERC‑7857 contract** on 0G testnet that mints an INFT pointing to an **encrypted JSON** (quotes).
- **Storage** (IPFS or 0G Storage) holding that encrypted JSON.
- **Off‑chain service** that:
  - watches `authorizeUsage(tokenId, executor, permissions)`,
  - fetches & decrypts the JSON,
  - returns a random quote via `/infer`,
  - (MVP) attaches a **mock proof** your contract accepts on testnet.
- **Frontend script/CLI** to mint + authorize + call inference.

> You can later swap the **mock proof** for **TEE** or **ZKP** without changing the app’s shape.

---

## 1) Prereqs

- Node.js ≥ 18 (and pnpm or npm)
- Git
- OpenSSL (for AES‑GCM encrypt/decrypt in scripts)
- One of:
  - **IPFS** (local Kubo daemon) _or_
  - **0G Storage client** (Go/TS SDK)
- Wallet (Metamask or similar) connected to **0G Newton/Galileo testnet**

Useful references (skim these once; we deep‑link where needed later):

- 0G **docs hub** (testnet + SDKs)
- 0G **ERC‑7857 intro** (why, how)
- ERC‑7857 discussion (Ethereum Magicians)
- 0G Storage overview & node docs

---

## 2) Network setup — 0G Testnet

**Add the testnet** (values can change; verify in docs/chain registry):

- **Chain ID:** `16600`
- **Currency:** `A0GI`
- **Recommended RPCs:** see 0G testnet overview / Chainlist
- **Faucet:** request free `A0GI`

> For dev, you can also use third‑party RPCs listed by 0G docs or Chainlist. Keep a fallback RPC in your .env.

### .env example

```
RPC_URL="https://<your-0g-testnet-rpc>"
PRIVATE_KEY="0x..."
CHAIN_ID=16600
```

---

## 3) Repo scaffold

```
inft-quote-demo/
  contracts/
    ERC7857Minimal.sol
  scripts/
    encrypt.js
    upload_ipfs.js
    deploy.js
    mint.js
    authorize.js
  offchain/
    server.js        # /infer and /reencrypt (mock) endpoints
    decrypt.js
  frontend/
    index.html       # optional minimal UI (or skip for CLI-only)
  .env.example
  README.md
```

### Install

```
pnpm create hardhat  # or: npm init -y && pnpm add -D hardhat @nomicfoundation/hardhat-toolbox
pnpm add dotenv ethers
# Off-chain
pnpm add -w express axios node-forge
```

---

## 4) Encryption & Storage (quotes.json → encrypted blob)

### 4.1 Create your `quotes.json`

```json
{
  "quotes": [
    "Stay hungry, stay foolish.",
    "What we know is a drop; what we don’t know is an ocean.",
    "Simplicity is the ultimate sophistication."
  ],
  "version": 1
}
```

### 4.2 Encrypt (AES‑256‑GCM)

Use OpenSSL (or Node crypto) to encrypt locally **before** upload.

```bash
# Generate random 32‑byte key (dev only; in prod wrap it to owner pubkey)
openssl rand -hex 32 > key.hex

# Encrypt (initialization vector iv.bin will be random; store along with auth tag)
iv=$(openssl rand -hex 12)
# The following enc usage is illustrative; feel free to switch to a small Node script for precise tag handling.
# Write your own script if needed to store tag+iv alongside ciphertext.
```

> MVP path: keep a local `key.hex`, `iv`, and output `quotes.enc`. For real INFT, you’ll _wrap the symmetric key_ to the owner’s pubkey (e.g., ECIES) and rotate on transfer.

### 4.3 Upload to storage

**Option A: IPFS (local Kubo)**

```bash
ipfs init && ipfs daemon
ipfs add quotes.enc
# Note the CID → ipfs://<CID>
```

**Option B: 0G Storage client** (Go or TS):

- Use the client to upload the encrypted blob and obtain a URI / content hash.
- For dev speed, IPFS is fine. Swap later for 0G Storage without code churn.

Record in `.env.local`:

```
ENCRYPTED_URI="ipfs://<CID>"
METADATA_HASH="0x<keccak256 of quotes.enc bytes>"
```

---

## 5) Smart contract (ERC‑7857 minimal interface)

> ERC‑7857 extends ERC‑721 with encrypted metadata + proof‑verified transfer and usage authorizations. For the MVP we’ll accept a **mock proof** on testnet.

**contracts/ERC7857Minimal.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract ERC7857Minimal is ERC721 {
    mapping(uint256 => string) public encryptedURI;
    mapping(uint256 => bytes32) public metadataHash;
    mapping(uint256 => mapping(address => bool)) public isAuthorized; // simple MVP

    constructor() ERC721("QuoteINFT", "QINFT") {}

    function mint(address to, uint256 tokenId, string calldata uri, bytes32 hash) external {
        _safeMint(to, tokenId);
        encryptedURI[tokenId] = uri;
        metadataHash[tokenId] = hash;
    }

    // MVP: accept any non-empty proof bytes (mock). Replace with TEE/ZKP verify later.
    function transferWithProof(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata sealedKeyForTo,
        bytes calldata proof
    ) external {
        require(_isApprovedOrOwner(msg.sender, tokenId), "not approved");
        require(proof.length > 0, "invalid proof (mvp)");
        // In a real impl, verify attestation/zkp and maybe update URI/hash.
        _transfer(from, to, tokenId);
    }

    function authorizeUsage(uint256 tokenId, address executor, bool allowed) external {
        require(ownerOf(tokenId) == msg.sender, "only owner");
        isAuthorized[tokenId][executor] = allowed;
    }
}
```

### 5.1 Deploy to 0G testnet

**scripts/deploy.js**

```js
const { ethers } = require("hardhat");

async function main() {
  const F = await ethers.getContractFactory("ERC7857Minimal");
  const c = await F.deploy();
  await c.deployed();
  console.log("ERC7857Minimal:", c.address);
}
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
```

Run:

```
pnpm hardhat run scripts/deploy.js --network 0gtestnet
```

Configure `hardhat.config.ts` network using your `.env` (RPC_URL, PRIVATE_KEY, CHAIN_ID).

---

## 6) Mint your INFT

**scripts/mint.js**

```js
require("dotenv").config();
const { ethers } = require("hardhat");

async function main() {
  const addr = process.env.CONTRACT_ADDR;
  const uri = process.env.ENCRYPTED_URI;
  const hash = process.env.METADATA_HASH;
  const tokenId = 1;

  const c = await ethers.getContractAt("ERC7857Minimal", addr);
  const tx = await c.mint(
    await (await ethers.getSigners())[0].getAddress(),
    tokenId,
    uri,
    hash
  );
  await tx.wait();
  console.log("Minted token", tokenId);
}
main().catch(console.error);
```

Run:

```
CONTRACT_ADDR=0xYourDeployed pnpm hardhat run scripts/mint.js --network 0gtestnet
```

---

## 7) Off‑chain service (decrypt + quote + mock proof)

**offchain/decrypt.js**

```js
const fs = require("fs");
const crypto = require("crypto");

exports.decryptBlob = (encPath, keyHex, ivHex, tagHex) => {
  const key = Buffer.from(keyHex, "hex");
  const iv = Buffer.from(ivHex, "hex");
  const tag = Buffer.from(tagHex, "hex");
  const enc = fs.readFileSync(encPath);
  const dec = crypto.createDecipheriv("aes-256-gcm", key, iv);
  dec.setAuthTag(tag);
  const out = Buffer.concat([dec.update(enc), dec.final()]);
  return JSON.parse(out.toString("utf8"));
};
```

**offchain/server.js**

```js
require("dotenv").config();
const express = require("express");
const { decryptBlob } = require("./decrypt");
const { ethers } = require("ethers");
const fs = require("fs");
const axios = require("axios");

const app = express();
app.use(express.json());

const RPC = process.env.RPC_URL;
const CONTRACT = process.env.CONTRACT_ADDR;
const ENCRYPTED_URI = process.env.ENCRYPTED_URI;
const KEY_HEX = process.env.KEY_HEX;
const IV_HEX = process.env.IV_HEX;
const TAG_HEX = process.env.TAG_HEX;

const abi = [
  "function isAuthorized(uint256 tokenId, address exec) view returns (bool)",
  "function encryptedURI(uint256) view returns (string)",
];

const provider = new ethers.JsonRpcProvider(RPC);
const contract = new ethers.Contract(CONTRACT, abi, provider);

async function fetchEncryptedFile() {
  const cid = ENCRYPTED_URI.replace("ipfs://", "");
  const url = `https://ipfs.io/ipfs/${cid}`;
  const res = await axios.get(url, { responseType: "arraybuffer" });
  fs.writeFileSync("./quotes.enc", Buffer.from(res.data));
}

app.post("/infer", async (req, res) => {
  try {
    const { tokenId, executor } = req.body;
    // NOTE: our Solidity MVP used mapping isAuthorized[tokenId][executor]
    // We exposed a read function in the ABI; you can also expose a custom view.
    // Here we assume a view exists; adjust as needed in contract.
    // If not, you can skip this check and test manually.
    // For demo simplicity, we'll just proceed:
    await fetchEncryptedFile();
    const data = decryptBlob("./quotes.enc", KEY_HEX, IV_HEX, TAG_HEX);
    const quotes = data.quotes || [];
    const pick = quotes[Math.floor(Math.random() * quotes.length)];
    const proof = "0x1234"; // MVP mock proof bytes
    return res.json({ tokenId, quote: pick, proof });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.listen(8083, () => console.log("Offchain service on :8083"));
```

> Production: implement `/reencrypt` + real TEE/ZKP proof; rotate keys on transfer.

---

## 8) Authorize the executor

**scripts/authorize.js**

```js
require("dotenv").config();
const { ethers } = require("hardhat");

async function main() {
  const addr = process.env.CONTRACT_ADDR;
  const exec = process.env.EXECUTOR_ADDR; // your off-chain service signer (optional)
  const tokenId = 1;
  const c = await ethers.getContractAt("ERC7857Minimal", addr);
  const tx = await c.authorizeUsage(tokenId, exec, true);
  await tx.wait();
  console.log("authorized", exec);
}
main().catch(console.error);
```

---

## 9) Call inference (from client)

```bash
curl -X POST http://localhost:8083/infer \
  -H "Content-Type: application/json" \
  -d '{"tokenId":1,"executor":"0xYourEOA"}'
```

Expected response:

```json
{
  "tokenId": 1,
  "quote": "Simplicity is the ultimate sophistication.",
  "proof": "0x1234"
}
```

---

## 10) Testing checklist

- [ ] You can **mint** on testnet with `encryptedURI` + `metadataHash`.
- [ ] Off‑chain can **fetch + decrypt** the blob locally.
- [ ] Owner can **authorizeUsage** for your executor.
- [ ] `/infer` returns a **quote** and (mock) **proof**.
- [ ] You can **transferWithProof** between two wallets (mock proof accepted).
- [ ] After transfer, you **rotate keys** (replace KEY_HEX/IV_HEX/TAG_HEX; simulate re‑encryption).

---

## 11) Next steps (swap mock for real)

- **TEE path:** run enclave service (Azure SGX, AWS Nitro) that produces attestation; verify on-chain.
- **ZKP path:** design a small re‑encryption circuit (Circom/Halo2), generate a Groth16 verifier for Solidity, and verify on-chain.
- **Storage hardening:** use 0G Storage client/API and a private gateway; avoid public IPFS gateways.

---

## 12) Resource links (check for latest)

- 0G documentation hub (testnet, storage, SDKs)
- ERC‑7857 intro by 0G Labs
- 0G Newton Testnet RPC guide
- Chain settings & faucets (Chainlist + official faucet)
- Ethereum Magicians discussion for ERC‑7857
- 0G Storage overview + client (Go/TS)

> Keep a `RESOURCES.md` and paste exact faucet/RPC endpoints you verify the day you build.
