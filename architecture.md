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
