declare class INFTOffChainService {
    private app;
    private provider;
    private inftContract;
    private oracleContract;
    private devKeys;
    private llmConfig;
    private llmCircuitBreaker;
    private port;
    constructor();
    /**
     * Initialize blockchain provider and contracts
     */
    private initializeBlockchain;
    /**
     * Load development keys for decryption
     */
    private loadDevKeys;
    /**
     * Load LLM configuration from environment variables
     */
    private loadLLMConfig;
    /**
     * Initialize LLM Circuit Breaker for resilient API calls
     */
    private initializeLLMCircuitBreaker;
    /**
     * Structured logging with metadata for Phase 3 observability
     */
    private logStructured;
    /**
     * Setup Express middleware
     */
    private setupMiddleware;
    /**
     * Setup API routes
     */
    private setupRoutes;
    /**
     * Handle inference requests
     */
    private handleInferRequest;
    /**
     * Handle streaming inference requests using Server-Sent Events (Phase 4)
     */
    private handleStreamingInferRequest;
    /**
     * Check if user is authorized to use the token
     */
    private checkAuthorization;
    /**
     * Fetch encrypted data from 0G Storage with comprehensive error handling
     */
    private fetchFromStorage;
    /**
     * Check if file is available in 0G Storage network
     */
    private checkFileAvailability;
    /**
     * Load local fallback file for development/testing
     */
    private loadLocalFallback;
    /**
     * Decrypt AES-GCM encrypted data
     */
    private decryptData;
    /**
     * Perform LLM-based inference on the decrypted data with circuit breaker
     */
    private performInference;
    /**
     * Build prompt template for LLM
     */
    private buildPrompt;
    /**
     * Direct LLM API call (wrapped by circuit breaker)
     */
    private callLLMDirect;
    /**
     * Streaming LLM API call for Server-Sent Events (Phase 4)
     */
    private callLLMDirectStreaming;
    /**
     * Enhanced LLM health check with diagnostics (Phase 3)
     */
    private handleLLMHealthCheck;
    /**
     * Generate oracle proof stub (extended with LLM metadata)
     */
    private generateOracleProof;
    /**
     * Start the service
     */
    start(): void;
}
export default INFTOffChainService;
//# sourceMappingURL=index.d.ts.map