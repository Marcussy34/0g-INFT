import { useAccount, useWriteContract, useReadContract, useWaitForTransactionReceipt } from 'wagmi'
import { parseEther, isAddress } from 'viem'
import { CONTRACT_ADDRESSES, INFT_ABI, OFFCHAIN_SERVICE_URL } from './constants'

/**
 * Custom hook for interacting with INFT contract
 * Provides functions for mint, authorize, transfer, and inference operations
 */
export function useINFT() {
  const { address: account, chain } = useAccount()
  const { writeContract, data: hash, isPending: isWritePending, error: writeError } = useWriteContract()
  
  // Wait for transaction confirmation
  const { isLoading: isConfirming, isSuccess: isConfirmed } = useWaitForTransactionReceipt({
    hash,
  })



  // Read functions
  const { data: currentTokenId } = useReadContract({
    address: CONTRACT_ADDRESSES.INFT,
    abi: INFT_ABI,
    functionName: 'getCurrentTokenId',
  })

  const { data: userBalance } = useReadContract({
    address: CONTRACT_ADDRESSES.INFT,
    abi: INFT_ABI,
    functionName: 'balanceOf',
    args: account ? [account] : undefined,
    query: { enabled: !!account }
  })

  // Mint INFT function
  const mintINFT = async (recipient, encryptedURI, metadataHash) => {
    console.log('mintINFT called with:', { recipient, encryptedURI, metadataHash })
    
    if (!isAddress(recipient)) {
      throw new Error('Invalid recipient address')
    }
    
    console.log('About to call writeContract with:', {
      address: CONTRACT_ADDRESSES.INFT,
      functionName: 'mint',
      args: [recipient, encryptedURI, metadataHash],
    })
    
    try {
      const result = await writeContract({
        address: CONTRACT_ADDRESSES.INFT,
        abi: INFT_ABI,
        functionName: 'mint',
        args: [recipient, encryptedURI, metadataHash],
      })
      console.log('writeContract result:', result)
      return result
    } catch (error) {
      console.error('Mint error:', error)
      throw error
    }
  }

  // Authorize usage function
  const authorizeUsage = async (tokenId, userAddress) => {
    if (!isAddress(userAddress)) {
      throw new Error('Invalid user address')
    }
    
    try {
      await writeContract({
        address: CONTRACT_ADDRESSES.INFT,
        abi: INFT_ABI,
        functionName: 'authorizeUsage',
        args: [BigInt(tokenId), userAddress],
      })
    } catch (error) {
      console.error('Authorize error:', error)
      throw error
    }
  }

  // Revoke usage function
  const revokeUsage = async (tokenId, userAddress) => {
    if (!isAddress(userAddress)) {
      throw new Error('Invalid user address')
    }
    
    try {
      await writeContract({
        address: CONTRACT_ADDRESSES.INFT,
        abi: INFT_ABI,
        functionName: 'revokeUsage',
        args: [BigInt(tokenId), userAddress],
      })
    } catch (error) {
      console.error('Revoke error:', error)
      throw error
    }
  }

  // Transfer INFT function (requires sealedKey and proof from TEE)
  const transferINFT = async (from, to, tokenId, sealedKey, proof) => {
    if (!isAddress(from) || !isAddress(to)) {
      throw new Error('Invalid from/to address')
    }
    
    try {
      await writeContract({
        address: CONTRACT_ADDRESSES.INFT,
        abi: INFT_ABI,
        functionName: 'transfer',
        args: [from, to, BigInt(tokenId), sealedKey, proof],
      })
    } catch (error) {
      console.error('Transfer error:', error)
      throw error
    }
  }

  // Clone INFT function
  const cloneINFT = async (from, to, tokenId, sealedKey, proof) => {
    if (!isAddress(from) || !isAddress(to)) {
      throw new Error('Invalid from/to address')
    }
    
    try {
      await writeContract({
        address: CONTRACT_ADDRESSES.INFT,
        abi: INFT_ABI,
        functionName: 'clone',
        args: [from, to, BigInt(tokenId), sealedKey, proof],
      })
    } catch (error) {
      console.error('Clone error:', error)
      throw error
    }
  }

  // Inference function (calls off-chain service)
  const performInference = async (tokenId, input) => {
    try {
      const response = await fetch(`${OFFCHAIN_SERVICE_URL}/infer`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          tokenId: parseInt(tokenId),
          input: input,
          user: account, // Optional: specify user for authorization check
        }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const result = await response.json()
      
      if (!result.success) {
        throw new Error(result.error || 'Inference failed')
      }

      return result
    } catch (error) {
      console.error('Inference error:', error)
      throw error
    }
  }

  // Check if user is authorized for a token
  const checkAuthorization = (tokenId, userAddress) => {
    return useReadContract({
      address: CONTRACT_ADDRESSES.INFT,
      abi: INFT_ABI,
      functionName: 'isAuthorized',
      args: [BigInt(tokenId), userAddress],
      query: { enabled: !!userAddress }
    })
  }

  // Get token owner
  const getTokenOwner = (tokenId) => {
    return useReadContract({
      address: CONTRACT_ADDRESSES.INFT,
      abi: INFT_ABI,
      functionName: 'ownerOf',
      args: [BigInt(tokenId)],
    })
  }

  // Get token metadata
  const getTokenMetadata = (tokenId) => {
    const { data: encryptedURI } = useReadContract({
      address: CONTRACT_ADDRESSES.INFT,
      abi: INFT_ABI,
      functionName: 'encryptedURI',
      args: [BigInt(tokenId)],
    })

    const { data: metadataHash } = useReadContract({
      address: CONTRACT_ADDRESSES.INFT,
      abi: INFT_ABI,
      functionName: 'metadataHash',
      args: [BigInt(tokenId)],
    })

    return { encryptedURI, metadataHash }
  }

  return {
    // Contract info
    currentTokenId,
    userBalance,
    
    // Write functions
    mintINFT,
    authorizeUsage,
    revokeUsage,
    transferINFT,
    cloneINFT,
    performInference,
    
    // Read functions
    checkAuthorization,
    getTokenOwner,
    getTokenMetadata,
    
    // Transaction state
    hash,
    isWritePending,
    isConfirming,
    isConfirmed,
    writeError,
  }
}
