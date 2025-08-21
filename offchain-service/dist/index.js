"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const crypto = __importStar(require("crypto"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const ethers_1 = require("ethers");
const dotenv = __importStar(require("dotenv"));
const axios_1 = __importDefault(require("axios"));
const express_rate_limit_1 = require("express-rate-limit");
const opossum_1 = __importDefault(require("opossum"));
const better_sse_1 = require("better-sse");
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
class INFTOffChainService {
    app;
    provider;
    inftContract;
    oracleContract;
    devKeys;
    llmConfig;
    llmCircuitBreaker;
    port;
    constructor() {
        this.app = (0, express_1.default)();
        this.port = parseInt(process.env.PORT || '3000');
        // Initialize blockchain connection
        this.initializeBlockchain();
        // Load development keys
        this.loadDevKeys();
        // Load LLM configuration
        this.loadLLMConfig();
        // Initialize circuit breaker for LLM calls
        this.initializeLLMCircuitBreaker();
        // Setup Express middleware
        this.setupMiddleware();
        // Setup routes
        this.setupRoutes();
    }
    /**
     * Initialize blockchain provider and contracts
     */
    initializeBlockchain() {
        const rpcUrl = process.env.GALILEO_RPC_URL || 'https://evmrpc-testnet.0g.ai';
        const inftAddress = process.env.INFT_CONTRACT_ADDRESS || '0x18db2ED477A25Aac615D803aE7be1d3598cdfF95';
        const oracleAddress = process.env.ORACLE_CONTRACT_ADDRESS || '0x567e70a52AB420c525D277b0020260a727A735dB';
        this.provider = new ethers_1.JsonRpcProvider(rpcUrl);
        this.inftContract = new ethers_1.Contract(inftAddress, INFT_ABI, this.provider);
        this.oracleContract = new ethers_1.Contract(oracleAddress, ORACLE_ABI, this.provider);
        console.log('🔗 Blockchain initialized:');
        console.log('  - RPC URL:', rpcUrl);
        console.log('  - INFT Contract:', inftAddress);
        console.log('  - Oracle Contract:', oracleAddress);
    }
    /**
     * Load development keys for decryption
     */
    loadDevKeys() {
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
     * Load LLM configuration from environment variables
     */
    loadLLMConfig() {
        this.llmConfig = {
            provider: process.env.LLM_PROVIDER || 'ollama',
            host: process.env.LLM_HOST || 'http://localhost:11434',
            model: process.env.LLM_MODEL || 'llama3.2:3b-instruct-q4_K_M',
            temperature: parseFloat(process.env.LLM_TEMPERATURE || '0.2'),
            maxTokens: parseInt(process.env.LLM_MAX_TOKENS || '256'),
            seed: parseInt(process.env.LLM_SEED || '42'),
            requestTimeoutMs: parseInt(process.env.LLM_REQUEST_TIMEOUT_MS || '20000'),
            maxContextQuotes: parseInt(process.env.LLM_MAX_CONTEXT_QUOTES || '25'),
            devFallback: process.env.LLM_DEV_FALLBACK === 'true'
        };
        console.log('🤖 LLM configuration loaded:');
        console.log('  - Provider:', this.llmConfig.provider);
        console.log('  - Host:', this.llmConfig.host);
        console.log('  - Model:', this.llmConfig.model);
        console.log('  - Temperature:', this.llmConfig.temperature);
        console.log('  - Max Tokens:', this.llmConfig.maxTokens);
        console.log('  - Dev Fallback:', this.llmConfig.devFallback);
    }
    /**
     * Initialize LLM Circuit Breaker for resilient API calls
     */
    initializeLLMCircuitBreaker() {
        const circuitBreakerOptions = {
            timeout: this.llmConfig.requestTimeoutMs,
            errorThresholdPercentage: 50, // Open circuit after 50% failures
            resetTimeout: 30000, // Try again after 30 seconds
            rollingCountTimeout: 10000, // 10 second rolling window
            rollingCountBuckets: 10,
            name: 'LLM-Ollama-Circuit',
            group: 'llm-calls'
        };
        this.llmCircuitBreaker = new opossum_1.default(this.callLLMDirect.bind(this), circuitBreakerOptions);
        // Add fallback for circuit breaker
        this.llmCircuitBreaker.fallback(() => {
            this.logStructured({
                requestId: 'circuit-fallback',
                tokenId: 0,
                userAddress: 'system',
                step: 'llm_circuit_fallback',
                error: 'Circuit breaker fallback triggered'
            });
            throw new Error('LLM_CIRCUIT_OPEN: Circuit breaker is open, failing fast');
        });
        // Circuit breaker event listeners for monitoring
        this.llmCircuitBreaker.on('open', () => {
            this.logStructured({
                requestId: 'circuit-event',
                tokenId: 0,
                userAddress: 'system',
                step: 'circuit_state_change',
                error: 'Circuit breaker opened - LLM service appears degraded'
            });
        });
        this.llmCircuitBreaker.on('halfOpen', () => {
            this.logStructured({
                requestId: 'circuit-event',
                tokenId: 0,
                userAddress: 'system',
                step: 'circuit_state_change'
            });
        });
        this.llmCircuitBreaker.on('close', () => {
            this.logStructured({
                requestId: 'circuit-event',
                tokenId: 0,
                userAddress: 'system',
                step: 'circuit_state_change'
            });
        });
        console.log('🔧 LLM Circuit Breaker initialized:');
        console.log('  - Timeout:', circuitBreakerOptions.timeout + 'ms');
        console.log('  - Error Threshold:', circuitBreakerOptions.errorThresholdPercentage + '%');
        console.log('  - Reset Timeout:', circuitBreakerOptions.resetTimeout + 'ms');
    }
    /**
     * Structured logging with metadata for Phase 3 observability
     */
    logStructured(context) {
        const timestamp = new Date().toISOString();
        const logLevel = context.error ? 'ERROR' : 'INFO';
        // Base log structure
        const logEntry = {
            timestamp,
            level: logLevel,
            service: '0g-inft-offchain',
            version: '2.0.0',
            requestId: context.requestId,
            tokenId: context.tokenId,
            userAddress: context.userAddress,
            step: context.step
        };
        // Add metrics if available
        if (context.metrics) {
            Object.assign(logEntry, {
                llm: {
                    provider: this.llmConfig.provider,
                    model: this.llmConfig.model,
                    duration_ms: context.metrics.duration,
                    token_count: context.metrics.tokenCount,
                    prompt_length: context.metrics.promptLength,
                    context_quotes: context.metrics.contextQuoteCount,
                    used_fallback: context.metrics.usedFallback,
                    circuit_state: context.metrics.circuitBreakerState
                }
            });
        }
        // Add error if present
        if (context.error) {
            Object.assign(logEntry, { error: context.error });
        }
        // Log in production-safe format (no full prompts/completions)
        console.log(JSON.stringify(logEntry));
    }
    /**
     * Setup Express middleware
     */
    setupMiddleware() {
        this.app.use((0, cors_1.default)());
        this.app.use(express_1.default.json());
        // Rate limiting for /infer endpoint (Phase 3 security)
        const inferRateLimit = (0, express_rate_limit_1.rateLimit)({
            windowMs: 60 * 1000, // 1 minute window
            limit: 30, // Limit each IP to 30 inference requests per minute
            message: {
                error: 'Too many inference requests. Please try again later.',
                code: 'RATE_LIMIT_EXCEEDED'
            },
            standardHeaders: true,
            legacyHeaders: false,
            skip: (req) => {
                // Skip rate limiting for health checks and other non-inference endpoints
                return !req.path.startsWith('/infer');
            }
        });
        this.app.use(inferRateLimit);
        // Request logging with structured format
        this.app.use((req, res, next) => {
            const requestId = crypto.randomUUID();
            req.headers['x-request-id'] = requestId;
            this.logStructured({
                requestId,
                tokenId: req.body?.tokenId || 0,
                userAddress: req.body?.user || 'unknown',
                step: 'request_received'
            });
            next();
        });
    }
    /**
     * Setup API routes
     */
    setupRoutes() {
        // Health check endpoint
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                service: '0G INFT Off-Chain Inference Service',
                timestamp: new Date().toISOString()
            });
        });
        // LLM health check endpoint
        this.app.get('/llm/health', this.handleLLMHealthCheck.bind(this));
        // Main inference endpoint
        this.app.post('/infer', this.handleInferRequest.bind(this));
        // Streaming inference endpoint (Phase 4 - SSE)
        this.app.post('/infer/stream', this.handleStreamingInferRequest.bind(this));
        // 404 handler
        this.app.use((req, res) => {
            res.status(404).json({ error: 'Endpoint not found' });
        });
    }
    /**
     * Handle inference requests
     */
    async handleInferRequest(req, res) {
        try {
            const request = req.body;
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
            const requestId = req.headers['x-request-id'] || crypto.randomUUID();
            // Enhanced input validation (Phase 3 security)
            if (request.input.length > 500) {
                this.logStructured({
                    requestId,
                    tokenId: request.tokenId,
                    userAddress: request.user || 'unknown',
                    step: 'input_validation_failed',
                    error: `Input too long: ${request.input.length} chars (max 500)`
                });
                res.status(400).json({
                    success: false,
                    error: 'Input too long. Maximum 500 characters allowed.',
                    code: 'INPUT_TOO_LONG'
                });
                return;
            }
            // Enhanced input sanitization with character filtering
            const sanitizedInput = request.input
                .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // Remove control characters
                .replace(/[^\w\s.,!?'"()-]/g, '') // Allow only alphanumeric, whitespace, and basic punctuation
                .trim();
            if (!sanitizedInput) {
                this.logStructured({
                    requestId,
                    tokenId: request.tokenId,
                    userAddress: request.user || 'unknown',
                    step: 'input_validation_failed',
                    error: 'Input contains only invalid characters after sanitization'
                });
                res.status(400).json({
                    success: false,
                    error: 'Input contains only invalid characters.',
                    code: 'INVALID_CHARACTERS'
                });
                return;
            }
            // Check for suspicious patterns
            const suspiciousPatterns = [
                /\b(system|admin|root|password|token|key|secret)\b/i,
                /<script|javascript:|data:/i,
                /\$\{.*\}/, // Template literal injection
                /`.*`/ // Backticks
            ];
            for (const pattern of suspiciousPatterns) {
                if (pattern.test(sanitizedInput)) {
                    this.logStructured({
                        requestId,
                        tokenId: request.tokenId,
                        userAddress: request.user || 'unknown',
                        step: 'input_validation_failed',
                        error: `Suspicious pattern detected in input`
                    });
                    res.status(400).json({
                        success: false,
                        error: 'Input contains suspicious content.',
                        code: 'SUSPICIOUS_INPUT'
                    });
                    return;
                }
            }
            this.logStructured({
                requestId,
                tokenId: request.tokenId,
                userAddress: request.user || 'unknown',
                step: 'processing_inference_request'
            });
            // Step 1: Check authorization on-chain
            const userAddress = request.user || process.env.DEFAULT_USER_ADDRESS || '0x32F91E4E2c60A9C16cAE736D3b42152B331c147F'; // Default to configured test address
            this.logStructured({
                requestId,
                tokenId: request.tokenId,
                userAddress,
                step: 'authorization_check_start'
            });
            const isAuthorized = await this.checkAuthorization(request.tokenId, userAddress);
            if (!isAuthorized) {
                this.logStructured({
                    requestId,
                    tokenId: request.tokenId,
                    userAddress,
                    step: 'authorization_failed',
                    error: 'User not authorized for token'
                });
                res.status(403).json({
                    success: false,
                    error: `User ${userAddress} is not authorized to use token ${request.tokenId}`,
                    code: 'UNAUTHORIZED',
                    metadata: {
                        tokenId: request.tokenId,
                        authorized: false,
                        timestamp: new Date().toISOString(),
                        proofHash: ''
                    }
                });
                return;
            }
            this.logStructured({
                requestId,
                tokenId: request.tokenId,
                userAddress,
                step: 'authorization_confirmed'
            });
            // Step 2: Fetch encrypted data from 0G Storage
            this.logStructured({
                requestId,
                tokenId: request.tokenId,
                userAddress,
                step: 'storage_fetch_start'
            });
            const encryptedData = await this.fetchFromStorage(this.devKeys.storageRootHash);
            // Step 3: Decrypt the data
            this.logStructured({
                requestId,
                tokenId: request.tokenId,
                userAddress,
                step: 'decryption_start'
            });
            const decryptedData = this.decryptData(encryptedData);
            // Step 4: Perform inference (LLM-based with fallback)
            const inferenceResult = await this.performInference(decryptedData, sanitizedInput, requestId);
            // Step 5: Generate oracle proof (extended with LLM metadata)
            this.logStructured({
                requestId,
                tokenId: request.tokenId,
                userAddress,
                step: 'proof_generation_start'
            });
            const proof = this.generateOracleProof(request.tokenId, sanitizedInput, inferenceResult.output, inferenceResult.metadata);
            // Step 6: Return response
            const response = {
                success: true,
                output: inferenceResult.output,
                proof: proof,
                metadata: {
                    tokenId: request.tokenId,
                    authorized: true,
                    timestamp: new Date().toISOString(),
                    proofHash: crypto.createHash('sha256').update(proof).digest('hex'),
                    provider: inferenceResult.metadata.provider,
                    model: inferenceResult.metadata.model,
                    temperature: inferenceResult.metadata.temperature,
                    promptHash: inferenceResult.metadata.promptHash,
                    contextHash: inferenceResult.metadata.contextHash,
                    completionHash: inferenceResult.metadata.completionHash
                }
            };
            this.logStructured({
                requestId,
                tokenId: request.tokenId,
                userAddress,
                step: 'inference_completed_success'
            });
            res.json(response);
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            const requestId = req.headers['x-request-id'] || 'unknown';
            this.logStructured({
                requestId,
                tokenId: req.body?.tokenId || 0,
                userAddress: req.body?.user || 'unknown',
                step: 'inference_request_failed',
                error: errorMessage
            });
            // Handle specific error types
            if (errorMessage.includes('LLM_UNAVAILABLE') || errorMessage.includes('LLM_CIRCUIT_OPEN')) {
                res.status(503).json({
                    success: false,
                    error: 'LLM service unavailable',
                    code: 'LLM_UNAVAILABLE'
                });
                return;
            }
            if (errorMessage.includes('RATE_LIMIT')) {
                res.status(429).json({
                    success: false,
                    error: 'Too many requests',
                    code: 'RATE_LIMIT_EXCEEDED'
                });
                return;
            }
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                code: 'INTERNAL_ERROR'
            });
        }
    }
    /**
     * Handle streaming inference requests using Server-Sent Events (Phase 4)
     */
    async handleStreamingInferRequest(req, res) {
        try {
            const request = req.body;
            // Same validation as regular inference endpoint
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
            const requestId = req.headers['x-request-id'] || crypto.randomUUID();
            // Enhanced input validation (same as regular endpoint)
            if (request.input.length > 500) {
                this.logStructured({
                    requestId,
                    tokenId: request.tokenId,
                    userAddress: request.user || 'unknown',
                    step: 'streaming_input_validation_failed',
                    error: `Input too long: ${request.input.length} chars (max 500)`
                });
                res.status(400).json({
                    success: false,
                    error: 'Input too long. Maximum 500 characters allowed.',
                    code: 'INPUT_TOO_LONG'
                });
                return;
            }
            // Enhanced input sanitization
            const sanitizedInput = request.input
                .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // Remove control characters
                .replace(/[^\w\s.,!?'"()-]/g, '') // Allow only alphanumeric, whitespace, and basic punctuation
                .trim();
            if (!sanitizedInput) {
                res.status(400).json({
                    success: false,
                    error: 'Input contains only invalid characters.',
                    code: 'INVALID_CHARACTERS'
                });
                return;
            }
            // Check for suspicious patterns
            const suspiciousPatterns = [
                /\b(system|admin|root|password|token|key|secret)\b/i,
                /<script|javascript:|data:/i,
                /\$\{.*\}/, // Template literal injection
                /`.*`/ // Backticks
            ];
            for (const pattern of suspiciousPatterns) {
                if (pattern.test(sanitizedInput)) {
                    res.status(400).json({
                        success: false,
                        error: 'Input contains suspicious content.',
                        code: 'SUSPICIOUS_INPUT'
                    });
                    return;
                }
            }
            this.logStructured({
                requestId,
                tokenId: request.tokenId,
                userAddress: request.user || 'unknown',
                step: 'processing_streaming_inference_request'
            });
            // Step 1: Check authorization on-chain
            const userAddress = request.user || process.env.DEFAULT_USER_ADDRESS || '0x32F91E4E2c60A9C16cAE736D3b42152B331c147F';
            const isAuthorized = await this.checkAuthorization(request.tokenId, userAddress);
            if (!isAuthorized) {
                this.logStructured({
                    requestId,
                    tokenId: request.tokenId,
                    userAddress,
                    step: 'authorization_failed'
                });
                res.status(403).json({
                    success: false,
                    error: 'User not authorized for this token',
                    code: 'UNAUTHORIZED'
                });
                return;
            }
            // Step 2: Create SSE session
            const session = await (0, better_sse_1.createSession)(req, res);
            this.logStructured({
                requestId,
                tokenId: request.tokenId,
                userAddress,
                step: 'sse_session_created'
            });
            // Send initial metadata
            session.push({
                type: 'start',
                tokenId: request.tokenId,
                userAddress,
                requestId,
                timestamp: new Date().toISOString(),
                provider: this.llmConfig.provider,
                model: this.llmConfig.model,
                temperature: this.llmConfig.temperature
            }, 'start');
            try {
                // Step 3: Download and decrypt data (same as regular endpoint)
                const encryptedData = await this.fetchFromStorage(this.devKeys.storageRootHash);
                const decryptedData = this.decryptData(encryptedData);
                // Step 4: Build prompt with context
                const contextQuotes = decryptedData.quotes
                    .slice(0, this.llmConfig.maxContextQuotes)
                    .map((quote, idx) => `${idx + 1}. "${quote}"`);
                const prompt = `You are a wise quote generator. Based on the user's request and the context quotes below, provide a thoughtful, relevant quote or response. Keep it concise and meaningful.

User request: "${sanitizedInput}"

Context quotes:
${contextQuotes.join('\n')}

Response:`;
                // Step 5: Perform streaming inference
                await this.callLLMDirectStreaming(prompt, session);
                this.logStructured({
                    requestId,
                    tokenId: request.tokenId,
                    userAddress,
                    step: 'streaming_inference_completed'
                });
            }
            catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                this.logStructured({
                    requestId,
                    tokenId: request.tokenId,
                    userAddress,
                    step: 'streaming_inference_failed',
                    error: errorMessage
                });
                // Send error to SSE client
                session.push({
                    type: 'error',
                    error: errorMessage,
                    code: 'INFERENCE_ERROR'
                }, 'error');
            }
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            const requestId = req.headers['x-request-id'] || 'unknown';
            this.logStructured({
                requestId,
                tokenId: req.body?.tokenId || 0,
                userAddress: req.body?.user || 'unknown',
                step: 'streaming_request_failed',
                error: errorMessage
            });
            // If SSE session wasn't created yet, return JSON error
            if (!res.headersSent) {
                res.status(500).json({
                    success: false,
                    error: 'Internal server error',
                    code: 'INTERNAL_ERROR'
                });
            }
        }
    }
    /**
     * Check if user is authorized to use the token
     */
    async checkAuthorization(tokenId, userAddress) {
        try {
            // Call the isAuthorized function from the INFT contract
            const authorized = await this.inftContract.isAuthorized(tokenId, userAddress);
            console.log(`🔍 Authorization check: Token ${tokenId}, User ${userAddress} -> ${authorized}`);
            return authorized;
        }
        catch (error) {
            console.error('❌ Error checking authorization:', error);
            return false;
        }
    }
    /**
     * Fetch encrypted data from 0G Storage with comprehensive error handling
     */
    async fetchFromStorage(rootHash) {
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
            }
            catch (downloadError) {
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
        }
        catch (error) {
            console.error('❌ 0G Storage download failed:', error instanceof Error ? error.message : String(error));
            console.log('⚠️ Falling back to local encrypted file');
            return this.loadLocalFallback();
        }
    }
    /**
     * Check if file is available in 0G Storage network
     */
    async checkFileAvailability(rootHash) {
        try {
            const indexerRpc = process.env.ZG_STORAGE_INDEXER || 'https://indexer-storage-testnet-turbo.0g.ai';
            const indexer = new Indexer(indexerRpc);
            console.log(`🔍 Checking file availability for: ${rootHash}`);
            const locations = await indexer.getFileLocations(rootHash);
            const available = locations !== null && (Array.isArray(locations) ? locations.length > 0 : true);
            console.log(`📍 File availability check: ${available ? '✅ Available' : '❌ Not available'}`);
            return available;
        }
        catch (error) {
            console.log(`⚠️ File availability check failed: ${error instanceof Error ? error.message : String(error)}`);
            return false;
        }
    }
    /**
     * Load local fallback file for development/testing
     */
    loadLocalFallback() {
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
    decryptData(encryptedBuffer) {
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
            const quotesData = JSON.parse(decrypted.toString('utf8'));
            console.log('✅ Data decrypted successfully');
            console.log('  - Total quotes:', quotesData.quotes.length);
            console.log('  - Category:', quotesData.metadata.category);
            return quotesData;
        }
        catch (error) {
            console.error('❌ Decryption failed:', error);
            throw new Error(`Failed to decrypt data: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    /**
     * Perform LLM-based inference on the decrypted data with circuit breaker
     */
    async performInference(quotesData, input, requestId = 'unknown') {
        const startTime = Date.now();
        const contextQuotes = quotesData.quotes.slice(0, this.llmConfig.maxContextQuotes);
        const prompt = this.buildPrompt(input, contextQuotes);
        // Generate hashes for proof
        const promptHash = crypto.createHash('sha256').update(prompt).digest('hex');
        const contextHash = crypto.createHash('sha256').update(JSON.stringify(contextQuotes)).digest('hex');
        // Initialize metrics
        const metrics = {
            startTime,
            promptLength: prompt.length,
            contextQuoteCount: contextQuotes.length,
            usedFallback: false,
            circuitBreakerState: this.llmCircuitBreaker.opened ? 'open' :
                this.llmCircuitBreaker.halfOpen ? 'half-open' : 'closed'
        };
        this.logStructured({
            requestId,
            tokenId: 0, // Will be set by caller
            userAddress: 'system',
            step: 'llm_inference_start',
            metrics
        });
        try {
            // Use circuit breaker for LLM call
            const completion = await this.llmCircuitBreaker.fire(prompt);
            metrics.endTime = Date.now();
            metrics.duration = metrics.endTime - metrics.startTime;
            metrics.tokenCount = completion.split(/\s+/).length; // Rough token estimate
            metrics.circuitBreakerState = this.llmCircuitBreaker.opened ? 'open' :
                this.llmCircuitBreaker.halfOpen ? 'half-open' : 'closed';
            const completionHash = crypto.createHash('sha256').update(completion).digest('hex');
            this.logStructured({
                requestId,
                tokenId: 0,
                userAddress: 'system',
                step: 'llm_inference_success',
                metrics
            });
            return {
                output: completion,
                metadata: {
                    provider: this.llmConfig.provider,
                    model: this.llmConfig.model,
                    temperature: this.llmConfig.temperature,
                    promptHash,
                    contextHash,
                    completionHash
                }
            };
        }
        catch (error) {
            metrics.endTime = Date.now();
            metrics.duration = metrics.endTime - metrics.startTime;
            metrics.circuitBreakerState = this.llmCircuitBreaker.opened ? 'open' :
                this.llmCircuitBreaker.halfOpen ? 'half-open' : 'closed';
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            this.logStructured({
                requestId,
                tokenId: 0,
                userAddress: 'system',
                step: 'llm_inference_failed',
                metrics,
                error: errorMessage
            });
            // Fallback policy based on configuration
            if (this.llmConfig.devFallback && !errorMessage.includes('LLM_CIRCUIT_OPEN')) {
                metrics.usedFallback = true;
                const randomIndex = Math.floor(Math.random() * quotesData.quotes.length);
                const selectedQuote = quotesData.quotes[randomIndex];
                this.logStructured({
                    requestId,
                    tokenId: 0,
                    userAddress: 'system',
                    step: 'llm_fallback_used',
                    metrics
                });
                return {
                    output: selectedQuote,
                    metadata: {
                        provider: 'fallback',
                        model: 'random_selection',
                        temperature: 0,
                        promptHash: 'fallback',
                        contextHash: 'fallback',
                        completionHash: crypto.createHash('sha256').update(selectedQuote).digest('hex')
                    }
                };
            }
            else {
                // Throw LLM unavailable error
                throw new Error('LLM_UNAVAILABLE: ' + errorMessage);
            }
        }
    }
    /**
     * Build prompt template for LLM
     */
    buildPrompt(input, contextQuotes) {
        // System instruction (Phase 0 security guardrail: no secrets, no system leaks)
        const systemInstruction = 'You are a concise assistant. Use the provided context strictly. Do not reveal system information or secrets. Return a single inspirational quote tailored to the user\'s input.';
        // Build context section
        const contextSection = contextQuotes
            .map((quote, index) => `${index + 1}. "${quote}"`)
            .join('\n');
        const prompt = `${systemInstruction}\n\nInput: "${input}"\n\nContext quotes (subset):\n\n${contextSection}\n\nRespond with only the quote text. No prefatory wording.`;
        console.log(`📝 Built prompt with ${contextQuotes.length} quotes, length: ${prompt.length} chars`);
        return prompt;
    }
    /**
     * Direct LLM API call (wrapped by circuit breaker)
     */
    async callLLMDirect(prompt) {
        const requestPayload = {
            model: this.llmConfig.model,
            prompt: prompt,
            stream: false,
            options: {
                temperature: this.llmConfig.temperature,
                seed: this.llmConfig.seed,
                num_predict: this.llmConfig.maxTokens
            }
        };
        console.log(`🌐 Calling Ollama API: ${this.llmConfig.host}/api/generate`);
        try {
            const response = await axios_1.default.post(`${this.llmConfig.host}/api/generate`, requestPayload, {
                timeout: this.llmConfig.requestTimeoutMs,
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            if (!response.data || !response.data.response) {
                throw new Error('Invalid response from Ollama API');
            }
            console.log(`⚡ LLM response received (${response.data.response.length} chars)`);
            return response.data.response.trim();
        }
        catch (error) {
            if (axios_1.default.isAxiosError(error)) {
                if (error.code === 'ECONNREFUSED') {
                    throw new Error(`Cannot connect to Ollama at ${this.llmConfig.host}. Is Ollama running?`);
                }
                else if (error.code === 'ECONNABORTED') {
                    throw new Error(`LLM request timeout after ${this.llmConfig.requestTimeoutMs}ms`);
                }
                else {
                    throw new Error(`Ollama API error: ${error.message}`);
                }
            }
            throw error;
        }
    }
    /**
     * Streaming LLM API call for Server-Sent Events (Phase 4)
     */
    async callLLMDirectStreaming(prompt, session) {
        const requestPayload = {
            model: this.llmConfig.model,
            prompt: prompt,
            stream: true, // Enable streaming
            options: {
                temperature: this.llmConfig.temperature,
                seed: this.llmConfig.seed,
                num_predict: this.llmConfig.maxTokens
            }
        };
        console.log(`🌐 Calling Ollama API (streaming): ${this.llmConfig.host}/api/generate`);
        try {
            const response = await axios_1.default.post(`${this.llmConfig.host}/api/generate`, requestPayload, {
                timeout: this.llmConfig.requestTimeoutMs,
                headers: {
                    'Content-Type': 'application/json'
                },
                responseType: 'stream'
            });
            let fullResponse = '';
            let tokenCount = 0;
            // Process the streaming response
            response.data.on('data', (chunk) => {
                const lines = chunk.toString().split('\n').filter(line => line.trim());
                for (const line of lines) {
                    try {
                        const data = JSON.parse(line);
                        if (data.response) {
                            fullResponse += data.response;
                            tokenCount++;
                            // Send token to SSE client
                            session.push({
                                type: 'token',
                                content: data.response,
                                tokenCount: tokenCount,
                                done: data.done || false
                            }, 'token');
                        }
                        // Check if stream is complete
                        if (data.done) {
                            // Send final completion event
                            session.push({
                                type: 'completion',
                                fullResponse: fullResponse,
                                totalTokens: tokenCount,
                                done: true
                            }, 'completion');
                            console.log(`⚡ Streaming LLM response completed (${tokenCount} tokens, ${fullResponse.length} chars)`);
                            return;
                        }
                    }
                    catch (parseError) {
                        // Skip invalid JSON lines
                        console.warn('Failed to parse streaming response line:', line);
                    }
                }
            });
            response.data.on('error', (error) => {
                console.error('Streaming response error:', error);
                session.push({
                    type: 'error',
                    error: error.message
                }, 'error');
            });
            response.data.on('end', () => {
                if (fullResponse === '') {
                    // Send error if no response received
                    session.push({
                        type: 'error',
                        error: 'No response received from LLM'
                    }, 'error');
                }
            });
        }
        catch (error) {
            console.error('Streaming LLM call error:', error);
            let errorMessage = 'Unknown error';
            if (axios_1.default.isAxiosError(error)) {
                if (error.code === 'ECONNREFUSED') {
                    errorMessage = `Cannot connect to Ollama at ${this.llmConfig.host}. Is Ollama running?`;
                }
                else if (error.code === 'ECONNABORTED') {
                    errorMessage = `LLM request timeout after ${this.llmConfig.requestTimeoutMs}ms`;
                }
                else {
                    errorMessage = `Ollama API error: ${error.message}`;
                }
            }
            else if (error instanceof Error) {
                errorMessage = error.message;
            }
            // Send error to SSE client
            session.push({
                type: 'error',
                error: errorMessage
            }, 'error');
        }
    }
    /**
     * Enhanced LLM health check with diagnostics (Phase 3)
     */
    async handleLLMHealthCheck(req, res) {
        const requestId = req.headers['x-request-id'] || crypto.randomUUID();
        this.logStructured({
            requestId,
            tokenId: 0,
            userAddress: 'health_check',
            step: 'llm_health_check_start'
        });
        try {
            const startTime = Date.now();
            // Test circuit breaker state and LLM connectivity
            const testResponse = await this.llmCircuitBreaker.fire('ping');
            const latency = Date.now() - startTime;
            // Get circuit breaker statistics
            const circuitStats = this.llmCircuitBreaker.stats;
            const healthData = {
                provider: this.llmConfig.provider,
                model: this.llmConfig.model,
                host: this.llmConfig.host,
                ok: true,
                latency_ms: latency,
                timestamp: new Date().toISOString(),
                circuit_breaker: {
                    state: this.llmCircuitBreaker.opened ? 'open' :
                        this.llmCircuitBreaker.halfOpen ? 'half-open' : 'closed',
                    stats: {
                        successes: circuitStats.successes,
                        failures: circuitStats.failures,
                        timeouts: circuitStats.timeouts,
                        fires: circuitStats.fires,
                        rejects: circuitStats.rejects,
                        fallbacks: circuitStats.fallbacks
                    }
                },
                config: {
                    timeout_ms: this.llmConfig.requestTimeoutMs,
                    max_tokens: this.llmConfig.maxTokens,
                    temperature: this.llmConfig.temperature,
                    fallback_enabled: this.llmConfig.devFallback
                }
            };
            this.logStructured({
                requestId,
                tokenId: 0,
                userAddress: 'health_check',
                step: 'llm_health_check_success',
                metrics: {
                    startTime,
                    endTime: Date.now(),
                    duration: latency,
                    promptLength: 4,
                    contextQuoteCount: 0,
                    usedFallback: false,
                    circuitBreakerState: healthData.circuit_breaker.state
                }
            });
            res.json(healthData);
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            this.logStructured({
                requestId,
                tokenId: 0,
                userAddress: 'health_check',
                step: 'llm_health_check_failed',
                error: errorMessage
            });
            res.status(503).json({
                provider: this.llmConfig.provider,
                model: this.llmConfig.model,
                host: this.llmConfig.host,
                ok: false,
                error: errorMessage,
                timestamp: new Date().toISOString(),
                circuit_breaker: {
                    state: this.llmCircuitBreaker.opened ? 'open' :
                        this.llmCircuitBreaker.halfOpen ? 'half-open' : 'closed'
                }
            });
        }
    }
    /**
     * Generate oracle proof stub (extended with LLM metadata)
     */
    generateOracleProof(tokenId, input, output, llmMetadata) {
        // Generate a proof stub that would be verified by the oracle
        // In a real implementation, this would be a TEE or ZKP proof
        const proofData = {
            tokenId,
            input,
            output,
            timestamp: new Date().toISOString(),
            service: '0G-INFT-OffChain-Service',
            version: '2.0.0',
            llm: {
                provider: llmMetadata.provider,
                model: llmMetadata.model,
                temperature: llmMetadata.temperature,
                promptHash: llmMetadata.promptHash,
                contextHash: llmMetadata.contextHash,
                completionHash: llmMetadata.completionHash
            }
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
            type: 'llm_stub'
        };
        return JSON.stringify(proof);
    }
    /**
     * Start the service
     */
    start() {
        this.app.listen(this.port, () => {
            console.log('🚀 0G INFT Off-Chain Inference Service Started');
            console.log('='.repeat(60));
            console.log(`🌐 Server running on http://localhost:${this.port}`);
            console.log('📋 Available endpoints:');
            console.log('  - GET  /health       - Service health check');
            console.log('  - GET  /llm/health   - LLM health check');
            console.log('  - POST /infer        - LLM inference endpoint');
            console.log('  - POST /infer/stream - LLM streaming inference (SSE)');
            console.log('');
            console.log('📝 Example curl command:');
            console.log(`curl -X POST http://localhost:${this.port}/infer \\`);
            console.log('  -H "Content-Type: application/json" \\');
            console.log('  -d \'{"tokenId": 1, "input": "inspire me"}\'');
            console.log('='.repeat(60));
        });
    }
}
// Initialize and start the service
if (require.main === module) {
    try {
        const service = new INFTOffChainService();
        service.start();
    }
    catch (error) {
        console.error('❌ Failed to start service:', error);
        process.exit(1);
    }
}
exports.default = INFTOffChainService;
//# sourceMappingURL=index.js.map