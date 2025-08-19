// 0G Network Configuration
export const ZERO_G_NETWORK = {
  id: 16601,
  name: '0G Galileo Testnet',
  nativeCurrency: {
    name: '0G',
    symbol: '0G',
    decimals: 18,
  },
  rpcUrls: {
    default: {
      http: ['https://evmrpc-testnet.0g.ai'],
    },
  },
  blockExplorers: {
    default: {
      name: '0G Galileo Block Explorer', 
      url: 'https://chainscan-galileo.0g.ai',
    },
  },
  testnet: true,
}

// Contract Addresses from deployments/galileo.json
export const CONTRACT_ADDRESSES = {
  INFT: '0xF170237160314f5D8526f981b251b56e25347Ed9',
  DATA_VERIFIER: '0x9C3FFe10e61B1750F61D2E0A64c6bBE8984BA268',
  ORACLE_STUB: '0x567e70a52AB420c525D277b0020260a727A735dB',
}

// Off-chain service configuration
export const OFFCHAIN_SERVICE_URL = 'http://localhost:3000'

// Contract ABIs (minimal required functions)
export const INFT_ABI = [
  'function mint(address to, string memory encryptedURI, bytes32 metadataHash) external returns (uint256)',
  'function authorizeUsage(uint256 tokenId, address user) external',
  'function revokeUsage(uint256 tokenId, address user) external', 
  'function transfer(address from, address to, uint256 tokenId, bytes calldata sealedKey, bytes calldata proof) external',
  'function clone(address from, address to, uint256 tokenId, bytes calldata sealedKey, bytes calldata proof) external returns (uint256)',
  'function isAuthorized(uint256 tokenId, address user) external view returns (bool)',
  'function ownerOf(uint256 tokenId) external view returns (address)',
  'function balanceOf(address owner) external view returns (uint256)',
  'function getCurrentTokenId() external view returns (uint256)',
  'function encryptedURI(uint256 tokenId) external view returns (string)',
  'function metadataHash(uint256 tokenId) external view returns (bytes32)',
  'function authorizedUsersOf(uint256 tokenId) external view returns (address[])',
  'function name() external view returns (string)',
  'function symbol() external view returns (string)',
  // Events
  'event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)',
  'event AuthorizedUsage(uint256 indexed tokenId, address indexed user, bool authorized)',
  'event Transferred(uint256 indexed tokenId, address indexed from, address indexed to, bytes32 proofHash)',
  'event Cloned(uint256 indexed originalTokenId, uint256 indexed newTokenId, address indexed to, bytes32 proofHash)',
]
