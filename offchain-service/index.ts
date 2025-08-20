import express from 'express';
import cors from 'cors';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { JsonRpcProvider, Contract, Wallet } from 'ethers';
import * as dotenv from 'dotenv';

// Load environment variables from parent directory and local
dotenv.config({ path: path.join(__dirname, '..', '.env') });
dotenv.config({ path: path.join(__dirname, '.env') });

// Import 0G Storage SDK
const { Indexer } = require('@0glabs/0g-ts-sdk');

/**
 * Phase 6 - Off-Chain Inference Service
 * 
 * This service provides secure AI inference capabilities for ERC-7857 INFT tokens.
 * It validates on-chain authorizations, fetches encrypted data from 0G Storage,
 * decrypts the data, performs inference, and returns results with oracle proofs.
 * 
 * Key Features:
 * - ERC-7857 authorization validation
 * - 0G Storage integration for encrypted data retrieval
 * - AES-GCM decryption
 * - Random quote inference
 * - Oracle proof generation (stub implementation)
 */

// INFT Contract ABI - only the functions we need
const INFT_ABI = [
  "function isAuthorized(uint256 tokenId, address user) view returns (bool)",
  "function ownerOf(uint256 tokenId) view returns (address)",
  "function tokenURI(uint256 tokenId) view returns (string)"
];

// Oracle Contract ABI - for generating proofs
const ORACLE_ABI = [
  "function verifyProof(bytes calldata data, bytes calldata proof) view returns (bool)"
];

interface InferRequest {
  tokenId: number;
  input: string;
  user?: string; // Optional - defaults to request origin or can be explicitly set
}

interface InferResponse {
  success: boolean;
  output?: string;
  proof?: string;
  error?: string;
  metadata?: {
    tokenId: number;
    authorized: boolean;
    timestamp: string;
    proofHash: string;
  };
}

interface QuotesData {
  version: string;
  quotes: string[];
  metadata: {
    created: string;
    description: string;
    totalQuotes: number;
    category: string;
  };
}

interface DevKeys {
  encryptedURI: string;
  storageRootHash: string;
  key: string;
  iv: string;
  tag: string;
}

class INFTOffChainService {
  private app: express.Application;
  private provider!: JsonRpcProvider;
  private inftContract!: Contract;
  private oracleContract!: Contract;
  private devKeys!: DevKeys;
  private port: number;

  constructor() {
    this.app = express();
    this.port = parseInt(process.env.PORT || '3000');
    
    // Initialize blockchain connection
    this.initializeBlockchain();
    
    // Load development keys
    this.loadDevKeys();
    
    // Setup Express middleware
    this.setupMiddleware();
    
    // Setup routes
    this.setupRoutes();
  }

  /**
   * Initialize blockchain provider and contracts
   */
  private initializeBlockchain(): void {
    const rpcUrl = process.env.GALILEO_RPC_URL || 'https://evmrpc-testnet.0g.ai';
    const inftAddress = process.env.INFT_CONTRACT_ADDRESS || '0xF170237160314f5D8526f981b251b56e25347Ed9';
    const oracleAddress = process.env.ORACLE_CONTRACT_ADDRESS || '0x567e70a52AB420c525D277b0020260a727A735dB';

    this.provider = new JsonRpcProvider(rpcUrl);
    this.inftContract = new Contract(inftAddress, INFT_ABI, this.provider);
    this.oracleContract = new Contract(oracleAddress, ORACLE_ABI, this.provider);

    console.log('🔗 Blockchain initialized:');
    console.log('  - RPC URL:', rpcUrl);
    console.log('  - INFT Contract:', inftAddress);
    console.log('  - Oracle Contract:', oracleAddress);
  }

  /**
   * Load development keys for decryption
   */
  private loadDevKeys(): void {
    const devKeysPath = path.join(__dirname, '..', 'storage', 'dev-keys.json');
    
    if (!fs.existsSync(devKeysPath)) {
      throw new Error(`Development keys not found at ${devKeysPath}`);
    }

    this.devKeys = JSON.parse(fs.readFileSync(devKeysPath, 'utf8'));
    console.log('🔑 Development keys loaded');
    console.log('  - Encrypted URI:', this.devKeys.encryptedURI);
    console.log('  - Storage Root Hash:', this.devKeys.storageRootHash);
  }

  /**
   * Setup Express middleware
   */
  private setupMiddleware(): void {
    this.app.use(cors());
    this.app.use(express.json());
    
    // Request logging
    this.app.use((req, res, next) => {
      console.log(`📨 ${req.method} ${req.path} - ${new Date().toISOString()}`);
      next();
    });
  }

  /**
   * Setup API routes
   */
  private setupRoutes(): void {
    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.json({ 
        status: 'healthy', 
        service: '0G INFT Off-Chain Inference Service',
        timestamp: new Date().toISOString()
      });
    });

    // Main inference endpoint
    this.app.post('/infer', this.handleInferRequest.bind(this));

    // 404 handler
    this.app.use((req, res) => {
      res.status(404).json({ error: 'Endpoint not found' });
    });
  }

  /**
   * Handle inference requests
   */
  private async handleInferRequest(req: express.Request, res: express.Response): Promise<void> {
    try {
      const request: InferRequest = req.body;
      
      // Validate request
      if (!request.tokenId || typeof request.tokenId !== 'number') {
        res.status(400).json({ 
          success: false, 
          error: 'Invalid tokenId. Must be a number.' 
        });
        return;
      }

      if (!request.input || typeof request.input !== 'string') {
        res.status(400).json({ 
          success: false, 
          error: 'Invalid input. Must be a non-empty string.' 
        });
        return;
      }

      console.log(`🎯 Processing inference request for token ${request.tokenId}`);

      // Step 1: Check authorization on-chain
      const userAddress = request.user || process.env.DEFAULT_USER_ADDRESS || '0x32F91E4E2c60A9C16cAE736D3b42152B331c147F'; // Default to configured test address
      const isAuthorized = await this.checkAuthorization(request.tokenId, userAddress);
      
      if (!isAuthorized) {
        res.status(403).json({
          success: false,
          error: `User ${userAddress} is not authorized to use token ${request.tokenId}`,
          metadata: {
            tokenId: request.tokenId,
            authorized: false,
            timestamp: new Date().toISOString(),
            proofHash: ''
          }
        });
        return;
      }

      console.log(`✅ Authorization confirmed for user ${userAddress} on token ${request.tokenId}`);

      // Step 2: Fetch encrypted data from 0G Storage
      console.log('📦 Fetching encrypted data from 0G Storage...');
      const encryptedData = await this.fetchFromStorage(this.devKeys.storageRootHash);

      // Step 3: Decrypt the data
      console.log('🔓 Decrypting data...');
      const decryptedData = this.decryptData(encryptedData);

      // Step 4: Perform inference (random quote selection)
      console.log('🤖 Performing inference...');
      const inferenceResult = this.performInference(decryptedData, request.input);

      // Step 5: Generate oracle proof (stub)
      console.log('📜 Generating oracle proof...');
      const proof = this.generateOracleProof(request.tokenId, request.input, inferenceResult);

      // Step 6: Return response
      const response: InferResponse = {
        success: true,
        output: inferenceResult,
        proof: proof,
        metadata: {
          tokenId: request.tokenId,
          authorized: true,
          timestamp: new Date().toISOString(),
          proofHash: crypto.createHash('sha256').update(proof).digest('hex')
        }
      };

      console.log(`🎉 Inference completed successfully for token ${request.tokenId}`);
      res.json(response);

    } catch (error) {
      console.error('❌ Error processing inference request:', error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Internal server error'
      });
    }
  }

  /**
   * Check if user is authorized to use the token
   */
  private async checkAuthorization(tokenId: number, userAddress: string): Promise<boolean> {
    try {
      // Call the isAuthorized function from the INFT contract
      const authorized = await this.inftContract.isAuthorized(tokenId, userAddress);
      console.log(`🔍 Authorization check: Token ${tokenId}, User ${userAddress} -> ${authorized}`);
      return authorized;
    } catch (error) {
      console.error('❌ Error checking authorization:', error);
      return false;
    }
  }

  /**
   * Fetch encrypted data from 0G Storage with comprehensive error handling
   */
  private async fetchFromStorage(rootHash: string): Promise<Buffer> {
    console.log(`📥 Fetching data from 0G Storage with root hash: ${rootHash}`);
    
    // First, check if file is available in the network
    const fileAvailable = await this.checkFileAvailability(rootHash);
    
    if (!fileAvailable) {
      console.log('⚠️ File not available in 0G Storage network, using local fallback');
      return this.loadLocalFallback();
    }
    
    try {
      // Get 0G Storage configuration
      const indexerRpc = process.env.ZG_STORAGE_INDEXER || 'https://indexer-storage-testnet-turbo.0g.ai';
      console.log('🔗 Using 0G Storage Indexer:', indexerRpc);
      
      // Initialize the 0G Storage Indexer
      const indexer = new Indexer(indexerRpc);
      
      // Create temporary file path for download
      const tempDir = path.join(__dirname, 'temp');
      if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
      }
      
      const tempFilePath = path.join(tempDir, `downloaded_${rootHash.substring(2, 12)}_${Date.now()}.enc`);
      
      // Ensure the file doesn't exist (SDK requirement)
      if (fs.existsSync(tempFilePath)) {
        fs.unlinkSync(tempFilePath);
      }
      
      console.log(`⬇️ Downloading from 0G Storage to: ${tempFilePath}`);
      
      // Download the file using 0G Storage SDK
      try {
        await indexer.download(rootHash, tempFilePath, true);
        console.log('✅ Download completed successfully');
      } catch (downloadError) {
        throw new Error(`0G Storage download failed: ${downloadError instanceof Error ? downloadError.message : String(downloadError)}`);
      }
      
      console.log('✅ Successfully downloaded from 0G Storage');
      
      // Read the downloaded file into buffer
      if (!fs.existsSync(tempFilePath)) {
        throw new Error('Downloaded file not found after 0G Storage download');
      }
      
      const fileBuffer = fs.readFileSync(tempFilePath);
      
      // Clean up temporary file
      fs.unlinkSync(tempFilePath);
      
      console.log(`📦 File size: ${fileBuffer.length} bytes`);
      return fileBuffer;
      
    } catch (error) {
      console.error('❌ 0G Storage download failed:', error instanceof Error ? error.message : String(error));
      console.log('⚠️ Falling back to local encrypted file');
      return this.loadLocalFallback();
    }
  }

  /**
   * Check if file is available in 0G Storage network
   */
  private async checkFileAvailability(rootHash: string): Promise<boolean> {
    try {
      const indexerRpc = process.env.ZG_STORAGE_INDEXER || 'https://indexer-storage-testnet-turbo.0g.ai';
      const indexer = new Indexer(indexerRpc);
      
      console.log(`🔍 Checking file availability for: ${rootHash}`);
      const locations = await indexer.getFileLocations(rootHash);
      
      const available = locations !== null && (Array.isArray(locations) ? locations.length > 0 : true);
      console.log(`📍 File availability check: ${available ? '✅ Available' : '❌ Not available'}`);
      
      return available;
    } catch (error) {
      console.log(`⚠️ File availability check failed: ${error instanceof Error ? error.message : String(error)}`);
      return false;
    }
  }

  /**
   * Load local fallback file for development/testing
   */
  private loadLocalFallback(): Buffer {
    const encryptedFilePath = path.join(__dirname, '..', 'storage', 'quotes.enc');
    
    if (!fs.existsSync(encryptedFilePath)) {
      throw new Error('Local fallback file not found. Please ensure storage/quotes.enc exists.');
    }
    
    console.log('📁 Using local fallback file:', encryptedFilePath);
    const buffer = fs.readFileSync(encryptedFilePath);
    console.log(`📦 Local file size: ${buffer.length} bytes`);
    
    return buffer;
  }

  /**
   * Decrypt AES-GCM encrypted data
   */
  private decryptData(encryptedBuffer: Buffer): QuotesData {
    try {
      // Extract components from the encrypted buffer
      // Format: [IV (12 bytes)][TAG (16 bytes)][ENCRYPTED_DATA]
      const iv = encryptedBuffer.subarray(0, 12);
      const tag = encryptedBuffer.subarray(12, 28);
      const encryptedData = encryptedBuffer.subarray(28);

      console.log('🔍 Decryption components:');
      console.log('  - IV length:', iv.length, 'bytes');
      console.log('  - Tag length:', tag.length, 'bytes');
      console.log('  - Encrypted data length:', encryptedData.length, 'bytes');

      // Convert hex key to buffer
      const key = Buffer.from(this.devKeys.key.replace('0x', ''), 'hex');

      // Create decipher
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);

      // Decrypt
      let decrypted = decipher.update(encryptedData);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      // Parse JSON
      const quotesData: QuotesData = JSON.parse(decrypted.toString('utf8'));
      
      console.log('✅ Data decrypted successfully');
      console.log('  - Total quotes:', quotesData.quotes.length);
      console.log('  - Category:', quotesData.metadata.category);

      return quotesData;

    } catch (error) {
      console.error('❌ Decryption failed:', error);
      throw new Error(`Failed to decrypt data: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Perform inference on the decrypted data
   */
  private performInference(quotesData: QuotesData, input: string): string {
    // Simple inference: return a random quote
    // In a real implementation, this would use the input to determine
    // which quote to return or perform more sophisticated inference
    
    const randomIndex = Math.floor(Math.random() * quotesData.quotes.length);
    const selectedQuote = quotesData.quotes[randomIndex];
    
    console.log(`🎲 Selected quote ${randomIndex + 1}/${quotesData.quotes.length}: "${selectedQuote.substring(0, 50)}..."`);
    
    return selectedQuote;
  }

  /**
   * Generate oracle proof stub
   */
  private generateOracleProof(tokenId: number, input: string, output: string): string {
    // Generate a proof stub that would be verified by the oracle
    // In a real implementation, this would be a TEE or ZKP proof
    
    const proofData = {
      tokenId,
      input,
      output,
      timestamp: new Date().toISOString(),
      service: '0G-INFT-OffChain-Service',
      version: '1.0.0'
    };

    // Create a simple proof hash for the stub
    const proofHash = crypto
      .createHash('sha256')
      .update(JSON.stringify(proofData))
      .digest('hex');

    const proof = {
      data: proofData,
      hash: proofHash,
      signature: 'stub_signature_' + proofHash.substring(0, 16),
      type: 'stub'
    };

    return JSON.stringify(proof);
  }

  /**
   * Start the service
   */
  public start(): void {
    this.app.listen(this.port, () => {
      console.log('🚀 0G INFT Off-Chain Inference Service Started');
      console.log('=' .repeat(60));
      console.log(`🌐 Server running on http://localhost:${this.port}`);
      console.log('📋 Available endpoints:');
      console.log('  - GET  /health - Health check');
      console.log('  - POST /infer  - Inference endpoint');
      console.log('');
      console.log('📝 Example curl command:');
      console.log(`curl -X POST http://localhost:${this.port}/infer \\`);
      console.log('  -H "Content-Type: application/json" \\');
      console.log('  -d \'{"tokenId": 1, "input": "inspire me"}\'');
      console.log('=' .repeat(60));
    });
  }
}

// Initialize and start the service
if (require.main === module) {
  try {
    const service = new INFTOffChainService();
    service.start();
  } catch (error) {
    console.error('❌ Failed to start service:', error);
    process.exit(1);
  }
}

export default INFTOffChainService;
