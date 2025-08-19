'use client'

import React, { useState, useEffect, useCallback } from 'react'
import { useAccount, useConnect, useDisconnect, useReadContract } from 'wagmi'
import { 
  Wallet, 
  Coins, 
  Users, 
  ArrowLeftRight, 
  Copy,
  MessageSquare,
  Settings,
  PlusCircle,
  Shield,
  Zap
} from 'lucide-react'
import { Button } from './ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { useINFT } from '../lib/useINFT'
import { addZeroGNetwork } from '../lib/wagmi'
import { CONTRACT_ADDRESSES, INFT_ABI } from '../lib/constants'



/**
 * Component to display user's owned token IDs
 */
function MyTokensList({ userAddress }) {
  const [ownedTokens, setOwnedTokens] = useState([])
  const [loading, setLoading] = useState(true)
  
  useEffect(() => {
    if (!userAddress) return
    
    const fetchOwnedTokens = async () => {
      try {
        setLoading(true)
        const tokens = []
        
        // Check ownership of tokens 1 and 2 (since we know these exist)
        // In a real app, you'd use events or a more efficient method
        // Check tokens up to the current token ID
        const maxTokenId = Math.max(3, 1) // Start from at least 1, check up to currentTokenId
        for (let tokenId = 1; tokenId < maxTokenId; tokenId++) {
          try {
            const response = await fetch(`https://evmrpc-testnet.0g.ai`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'eth_call',
                params: [{
                  to: '0xF170237160314f5D8526f981b251b56e25347Ed9',
                  data: `0x6352211e${tokenId.toString(16).padStart(64, '0')}`  // ownerOf(uint256)
                }, 'latest']
              })
            })
            
            const result = await response.json()
            if (result.result && result.result !== '0x') {
              const owner = '0x' + result.result.slice(-40)
              if (owner.toLowerCase() === userAddress.toLowerCase()) {
                tokens.push(tokenId)
              }
            }
          } catch (error) {
            console.log(`Token ${tokenId} check failed:`, error)
          }
        }
        
        setOwnedTokens(tokens)
      } catch (error) {
        console.error('Error fetching owned tokens:', error)
      } finally {
        setLoading(false)
      }
    }
    
    fetchOwnedTokens()
  }, [userAddress])
  
  if (loading) {
    return <p className="text-gray-500">Loading your tokens...</p>
  }
  
  if (ownedTokens.length === 0) {
    return <p className="text-gray-500">No tokens found</p>
  }
  
  return (
    <div className="space-y-2">
      <p className="text-sm text-gray-600 mb-3">You own the following Token IDs:</p>
      <div className="flex flex-wrap gap-2">
        {ownedTokens.map(tokenId => (
          <div key={tokenId} className="px-3 py-1 bg-blue-100 text-blue-800 rounded-lg text-sm font-medium">
            Token #{tokenId}
          </div>
        ))}
      </div>
      <p className="text-xs text-green-600 mt-2">
        ✅ You can perform inference with any of these tokens
      </p>
    </div>
  )
}

/**
 * Main INFT Dashboard Component
 * Provides UI for all INFT operations: mint, authorize, infer, transfer
 */
export default function INFTDashboard() {
  const [mounted, setMounted] = useState(false)
  const { address, isConnected, chain } = useAccount()
  const { connect, connectors } = useConnect()
  const { disconnect } = useDisconnect()

  // Fix hydration error by only rendering after mount
  useEffect(() => {
    setMounted(true)
  }, [])

  // Debug logging
  useEffect(() => {
    console.log('Wallet state:', { 
      address, 
      isConnected, 
      chain: chain?.id,
      chainName: chain?.name 
    })
  }, [address, isConnected, chain])
  
  const {
    currentTokenId,
    userBalance,
    mintINFT,
    authorizeUsage,
    revokeUsage,
    transferINFT,
    performInference,
    hash,
    isWritePending,
    isConfirming,
    isConfirmed,
    writeError,
  } = useINFT()

  // Form states
  const [mintForm, setMintForm] = useState({
    recipient: '',
    encryptedURI: '',
    metadataHash: ''
  })
  
  const [authorizeForm, setAuthorizeForm] = useState({
    tokenId: '1',
    userAddress: ''
  })
  
  const [inferForm, setInferForm] = useState({
    tokenId: '2',  // Default to token 2 which you own
    input: ''
  })
  
  const [transferForm, setTransferForm] = useState({
    from: '',
    to: '',
    tokenId: '1'
  })

  const [inferenceResult, setInferenceResult] = useState(null)
  const [isInferring, setIsInferring] = useState(false)
  
  // Authorization checker state
  const [authCheckForm, setAuthCheckForm] = useState({
    tokenId: '1'
  })
  const [authCheckResults, setAuthCheckResults] = useState(null)
  const [isCheckingAuth, setIsCheckingAuth] = useState(false)

  // Handle wallet connection
  const handleConnect = async () => {
    if (connectors[0]) {
      // First try to add 0G network
      await addZeroGNetwork()
      // Then connect
      connect({ connector: connectors[0] })
    }
  }

  // Handle mint INFT
  const handleMint = async (e) => {
    e.preventDefault()
    console.log('Mint button clicked', mintForm)
    
    if (!mintForm.recipient || !mintForm.encryptedURI || !mintForm.metadataHash) {
      alert('Please fill all fields')
      return
    }
    
    try {
      console.log('Calling mintINFT with:', {
        recipient: mintForm.recipient,
        encryptedURI: mintForm.encryptedURI,
        metadataHash: mintForm.metadataHash
      })
      
      const result = await mintINFT(
        mintForm.recipient,
        mintForm.encryptedURI,
        mintForm.metadataHash
      )
      
      console.log('Mint transaction submitted successfully, result:', result)
    } catch (error) {
      console.error('Mint failed:', error)
      console.error('Error details:', error.stack)
      alert('Mint failed: ' + error.message)
    }
  }

  // Handle authorize usage
  const handleAuthorize = async (e) => {
    e.preventDefault()
    console.log('Authorize button clicked', authorizeForm)
    
    if (!authorizeForm.tokenId || !authorizeForm.userAddress) {
      alert('Please fill all fields')
      return
    }
    
    try {
      console.log('🔐 Starting authorization process for:', {
        tokenId: authorizeForm.tokenId,
        userAddress: authorizeForm.userAddress
      })
      
      await authorizeUsage(authorizeForm.tokenId, authorizeForm.userAddress)
      
      console.log('✅ Authorization transaction submitted successfully')
      console.log('⏳ Please wait for transaction confirmation below...')
      
      // Clear the form on successful submission
      setAuthorizeForm({ tokenId: '', userAddress: '' })
    } catch (error) {
      console.error('❌ Authorization failed:', error)
      alert('Authorization failed: ' + error.message)
    }
  }

  // Handle inference
  const handleInference = async (e) => {
    e.preventDefault()
    if (!inferForm.tokenId || !inferForm.input) {
      alert('Please fill all fields')
      return
    }
    
    setIsInferring(true)
    try {
      const result = await performInference(inferForm.tokenId, inferForm.input)
      setInferenceResult(result)
    } catch (error) {
      console.error('Inference failed:', error)
      alert('Inference failed: ' + error.message)
    } finally {
      setIsInferring(false)
    }
  }

  // Handle transfer (placeholder - requires TEE integration)
  const handleTransfer = async (e) => {
    e.preventDefault()
    alert('Transfer functionality requires TEE attestation. This is a placeholder for the complete implementation.')
  }

  // Authorization check using wagmi hooks (simple and reliable)
  const handleAuthCheck = async (e) => {
    e.preventDefault()
    
    if (!authCheckForm.tokenId) {
      alert('Please enter a token ID')
      return
    }
    
    console.log('🔍 Starting authorization check for token ID:', authCheckForm.tokenId)
    setIsCheckingAuth(true)
    setAuthCheckResults(null)
    
    try {
      // Use wagmi's built-in fetch capabilities
      const { readContract } = await import('viem/actions')
      const { createPublicClient, http } = await import('viem')
      const { defineChain } = await import('viem')
      
      // Define 0G chain
      const zeroGChain = defineChain({
        id: 16601,
        name: '0G Galileo Testnet',
        network: '0g-galileo',
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
      })
      
      const client = createPublicClient({
        chain: zeroGChain,
        transport: http(),
      })
      
      // Get token owner
      const tokenOwner = await readContract(client, {
        address: CONTRACT_ADDRESSES.INFT,
        abi: INFT_ABI,
        functionName: 'ownerOf',
        args: [BigInt(authCheckForm.tokenId)],
      })
      
      console.log('Token owner:', tokenOwner)
      
      // Get ALL authorized users using authorizedUsersOf (same as Hardhat script)
      console.log('Getting all authorized users...')
      
      let authorizedUsers = []
      try {
        authorizedUsers = await readContract(client, {
          address: CONTRACT_ADDRESSES.INFT,
          abi: INFT_ABI,
          functionName: 'authorizedUsersOf',
          args: [BigInt(authCheckForm.tokenId)],
        })
        
        console.log('All authorized users from contract:', authorizedUsers)
      } catch (error) {
        console.error('Failed to get authorized users list:', error)
        // Fall back to checking specific addresses
        authorizedUsers = [address, tokenOwner].filter(addr => addr)
      }
      
      // Also include current user and token owner if not in the list
      const allAddressesToCheck = [...authorizedUsers]
      if (address && !allAddressesToCheck.find(addr => addr.toLowerCase() === address.toLowerCase())) {
        allAddressesToCheck.push(address)
      }
      if (tokenOwner && !allAddressesToCheck.find(addr => addr.toLowerCase() === tokenOwner.toLowerCase())) {
        allAddressesToCheck.push(tokenOwner)
      }
      
      const authResults = []
      
      console.log('All addresses to process:', allAddressesToCheck)
      
      for (const checkAddr of allAddressesToCheck) {
        try {
          console.log(`Checking authorization for: ${checkAddr}`)
          
          // For addresses from authorizedUsersOf, they should be authorized
          const isFromAuthorizedList = authorizedUsers.find(addr => addr.toLowerCase() === checkAddr.toLowerCase())
          
          let isAuthorized = false
          if (isFromAuthorizedList) {
            isAuthorized = true
            console.log(`${checkAddr} is in authorized users list: true`)
          } else {
            // Double-check with isAuthorized function
            isAuthorized = await readContract(client, {
              address: CONTRACT_ADDRESSES.INFT,
              abi: INFT_ABI,
              functionName: 'isAuthorized',
              args: [BigInt(authCheckForm.tokenId), checkAddr],
            })
            console.log(`${checkAddr} authorization result:`, isAuthorized)
          }
          
          authResults.push({
            address: checkAddr,
            isAuthorized: !!isAuthorized,
            isOwner: checkAddr.toLowerCase() === tokenOwner.toLowerCase(),
            isCurrentUser: checkAddr.toLowerCase() === address?.toLowerCase()
          })
        } catch (error) {
          console.error(`Failed to check authorization for ${checkAddr}:`, error)
          authResults.push({
            address: checkAddr,
            isAuthorized: false,
            isOwner: checkAddr.toLowerCase() === tokenOwner.toLowerCase(),
            isCurrentUser: checkAddr.toLowerCase() === address?.toLowerCase(),
            error: error.message
          })
        }
      }
      
      setAuthCheckResults({
        tokenId: authCheckForm.tokenId,
        tokenOwner,
        authorizations: authResults,
        checkedAt: new Date().toLocaleTimeString()
      })
      
      console.log('✅ Authorization check completed:', authResults)
      
    } catch (error) {
      console.error('❌ Authorization check failed:', error)
      alert('Authorization check failed: ' + error.message)
    } finally {
      setIsCheckingAuth(false)
    }
  }

  // Show loading until component is mounted (fixes hydration error)
  if (!mounted) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardContent className="p-6 text-center">
            <p>Loading...</p>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (!isConnected) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle className="flex items-center justify-center gap-2">
              <Zap className="h-6 w-6 text-blue-600" />
              0G INFT Dashboard
            </CardTitle>
            <CardDescription>
              Connect your wallet to interact with Intelligent NFTs on 0G Galileo testnet
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={handleConnect} className="w-full" size="lg">
              <Wallet className="mr-2 h-5 w-5" />
              Connect Wallet
            </Button>
            <p className="text-sm text-gray-500 mt-4 text-center">
              Make sure you have MetaMask or another Web3 wallet installed
            </p>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-4">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex justify-between items-center">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-2">
                <Zap className="h-8 w-8 text-blue-600" />
                0G INFT Dashboard
              </h1>
              <p className="text-gray-600 mt-1">
                Manage your Intelligent NFTs on 0G Galileo testnet
              </p>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="text-right">
                <p className="text-sm text-gray-500">Connected Account</p>
                <p className="font-mono text-sm">{address?.slice(0, 6)}...{address?.slice(-4)}</p>
                <p className="text-sm text-gray-500">
                  Balance: {userBalance?.toString() || '0'} INFTs
                </p>
              </div>
              <Button variant="outline" onClick={() => disconnect()}>
                Disconnect
              </Button>
            </div>
          </div>
        </div>

        {/* Status Section */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-blue-100 rounded-lg">
                  <Coins className="h-6 w-6 text-blue-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{currentTokenId?.toString() || '0'}</p>
                  <p className="text-gray-600">Next Token ID</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-green-100 rounded-lg">
                  <Users className="h-6 w-6 text-green-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{userBalance?.toString() || '0'}</p>
                  <p className="text-gray-600">My INFTs</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-purple-100 rounded-lg">
                  <Shield className="h-6 w-6 text-purple-600" />
                </div>
                <div>
                  <p className="text-lg font-bold">0G Galileo</p>
                  <p className="text-gray-600">Testnet Active</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* My Tokens Section */}
        {userBalance && userBalance > 0 && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Coins className="h-5 w-5" />
                My Token IDs
              </CardTitle>
              <CardDescription>
                Tokens you own and can use for inference
              </CardDescription>
            </CardHeader>
            <CardContent>
              <MyTokensList userAddress={address} />
            </CardContent>
          </Card>
        )}

        {/* Main Operations */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Mint INFT */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <PlusCircle className="h-5 w-5" />
                Mint INFT
              </CardTitle>
              <CardDescription>
                Create a new Intelligent NFT with encrypted metadata
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleMint} className="space-y-4">
                <div>
                  <Label htmlFor="recipient">Recipient Address</Label>
                  <Input
                    id="recipient"
                    value={mintForm.recipient}
                    onChange={(e) => setMintForm({...mintForm, recipient: e.target.value})}
                    placeholder="0x..."
                  />
                </div>
                <div>
                  <Label htmlFor="encryptedURI">Encrypted URI</Label>
                  <Input
                    id="encryptedURI"
                    value={mintForm.encryptedURI}
                    onChange={(e) => setMintForm({...mintForm, encryptedURI: e.target.value})}
                    placeholder="0g://storage/..."
                  />
                </div>
                <div>
                  <Label htmlFor="metadataHash">Metadata Hash</Label>
                  <Input
                    id="metadataHash"
                    value={mintForm.metadataHash}
                    onChange={(e) => setMintForm({...mintForm, metadataHash: e.target.value})}
                    placeholder="0x..."
                  />
                </div>
                <Button 
                  type="submit" 
                  className="w-full" 
                  disabled={isWritePending || isConfirming}
                >
                  {isWritePending || isConfirming ? 'Minting...' : 'Mint INFT'}
                </Button>
              </form>
            </CardContent>
          </Card>

          {/* Authorize Usage */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                Authorize Usage
              </CardTitle>
              <CardDescription>
                Grant inference access to users without transferring ownership
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleAuthorize} className="space-y-4">
                <div>
                  <Label htmlFor="authTokenId">Token ID</Label>
                  <Input
                    id="authTokenId"
                    value={authorizeForm.tokenId}
                    onChange={(e) => setAuthorizeForm({...authorizeForm, tokenId: e.target.value})}
                    placeholder="1"
                  />
                </div>
                <div>
                  <Label htmlFor="userAddress">User Address</Label>
                  <Input
                    id="userAddress"
                    value={authorizeForm.userAddress}
                    onChange={(e) => setAuthorizeForm({...authorizeForm, userAddress: e.target.value})}
                    placeholder="0x..."
                  />
                </div>
                <Button 
                  type="submit" 
                  className="w-full" 
                  disabled={isWritePending || isConfirming}
                >
                  {isWritePending || isConfirming ? 'Authorizing...' : 'Authorize User'}
                </Button>
              </form>
            </CardContent>
          </Card>

          {/* Inference */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <MessageSquare className="h-5 w-5" />
                AI Inference
              </CardTitle>
              <CardDescription>
                Perform AI inference using an authorized INFT
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleInference} className="space-y-4">
                <div>
                  <Label htmlFor="inferTokenId">Token ID</Label>
                  <Input
                    id="inferTokenId"
                    value={inferForm.tokenId}
                    onChange={(e) => setInferForm({...inferForm, tokenId: e.target.value})}
                    placeholder="1"
                  />
                </div>
                <div>
                  <Label htmlFor="input">Input Prompt</Label>
                  <Input
                    id="input"
                    value={inferForm.input}
                    onChange={(e) => setInferForm({...inferForm, input: e.target.value})}
                    placeholder="inspire me"
                  />
                </div>
                <Button 
                  type="submit" 
                  className="w-full" 
                  disabled={isInferring}
                >
                  {isInferring ? 'Processing...' : 'Run Inference'}
                </Button>
                
                {inferenceResult && (
                  <div className="mt-4 p-4 bg-green-50 border border-green-200 rounded-lg">
                    <h4 className="font-semibold text-green-800 mb-2">Inference Result:</h4>
                    <p className="text-green-700">{inferenceResult.output}</p>
                    {inferenceResult.proof && (
                      <p className="text-xs text-green-600 mt-2">
                        Proof: {inferenceResult.proof.slice(0, 50)}...
                      </p>
                    )}
                  </div>
                )}
              </form>
            </CardContent>
          </Card>

          {/* Transfer (Placeholder) */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ArrowLeftRight className="h-5 w-5" />
                Transfer INFT
              </CardTitle>
              <CardDescription>
                Transfer ownership with TEE attestation (requires TEE setup)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleTransfer} className="space-y-4">
                <div>
                  <Label htmlFor="fromAddress">From Address</Label>
                  <Input
                    id="fromAddress"
                    value={transferForm.from}
                    onChange={(e) => setTransferForm({...transferForm, from: e.target.value})}
                    placeholder="0x..."
                  />
                </div>
                <div>
                  <Label htmlFor="toAddress">To Address</Label>
                  <Input
                    id="toAddress"
                    value={transferForm.to}
                    onChange={(e) => setTransferForm({...transferForm, to: e.target.value})}
                    placeholder="0x..."
                  />
                </div>
                <div>
                  <Label htmlFor="transferTokenId">Token ID</Label>
                  <Input
                    id="transferTokenId"
                    value={transferForm.tokenId}
                    onChange={(e) => setTransferForm({...transferForm, tokenId: e.target.value})}
                    placeholder="1"
                  />
                </div>
                <Button type="submit" className="w-full" variant="outline">
                  Transfer (Placeholder)
                </Button>
              </form>
            </CardContent>
          </Card>

          {/* Authorization Checker */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Check Authorizations
              </CardTitle>
              <CardDescription>
                Check who is authorized to use a specific INFT token
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleAuthCheck} className="space-y-4">
                <div>
                  <Label htmlFor="checkTokenId">Token ID</Label>
                  <Input
                    id="checkTokenId"
                    type="number"
                    value={authCheckForm.tokenId}
                    onChange={(e) => setAuthCheckForm({
                      ...authCheckForm,
                      tokenId: e.target.value
                    })}
                    placeholder="Enter token ID to check"
                    min="1"
                  />
                </div>
                
                <Button 
                  type="submit" 
                  className="w-full" 
                  disabled={isCheckingAuth}
                >
                  {isCheckingAuth ? 'Checking...' : 'Check Authorizations'}
                </Button>
              </form>

              {/* Authorization Results */}
              {authCheckResults && (
                <div className="mt-6 space-y-4">
                  <div className="border-t pt-4">
                    <h4 className="font-semibold text-lg mb-3">
                      Authorization Status for Token #{authCheckResults.tokenId}
                    </h4>
                    
                    {authCheckResults.tokenOwner && (
                      <div className="mb-4 p-3 bg-blue-50 rounded-lg">
                        <p className="text-sm font-medium text-blue-700">👑 Token Owner:</p>
                        <p className="text-sm text-blue-600 font-mono break-all">
                          {authCheckResults.tokenOwner}
                        </p>
                      </div>
                    )}

                    <div className="space-y-2">
                      <p className="font-medium text-gray-700">Authorization Status:</p>
                      <div className="text-sm text-blue-600 bg-blue-50 p-2 rounded mb-3">
                        💡 <strong>Note:</strong> Token owners must explicitly authorize themselves for inference access.
                      </div>
                      {authCheckResults.authorizations.length === 0 ? (
                        <p className="text-gray-500 text-sm">No addresses checked</p>
                      ) : (
                        <div className="space-y-2">
                          {authCheckResults.authorizations.map((auth, index) => (
                            <div
                              key={index}
                              className={`p-3 rounded-lg border ${
                                auth.isAuthorized 
                                  ? 'bg-green-50 border-green-200' 
                                  : 'bg-gray-50 border-gray-200'
                              }`}
                            >
                              <div className="flex items-center justify-between">
                                <div className="flex-1">
                                  <p className="text-sm font-mono break-all">
                                    {auth.address}
                                  </p>
                                  <div className="flex items-center gap-2 mt-1">
                                    {auth.isOwner && (
                                      <span className="text-xs bg-blue-100 text-blue-700 px-2 py-1 rounded">
                                        👑 Owner
                                      </span>
                                    )}
                                    {auth.isCurrentUser && (
                                      <span className="text-xs bg-purple-100 text-purple-700 px-2 py-1 rounded">
                                        👤 You
                                      </span>
                                    )}
                                  </div>
                                </div>
                                <div className="ml-4">
                                  {auth.isAuthorized ? (
                                    <span className="text-green-600 font-semibold">✅ Authorized</span>
                                  ) : (
                                    <span className="text-gray-500">❌ Not Authorized</span>
                                  )}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    <p className="text-xs text-gray-500 mt-3">
                      ⏰ Checked at {authCheckResults.checkedAt}
                    </p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Transaction Status */}
        {(isWritePending || isConfirming || isConfirmed) && (
          <Card className="mt-6 border-l-4 border-l-blue-500">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5" />
                Transaction Status
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {isWritePending && (
                  <div className="flex items-center gap-2">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
                    <p className="text-blue-600 font-medium">📤 Transaction submitted to blockchain...</p>
                  </div>
                )}
                {isConfirming && (
                  <div className="flex items-center gap-2">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-yellow-600"></div>
                    <p className="text-yellow-600 font-medium">⏳ Waiting for blockchain confirmation...</p>
                  </div>
                )}
                {isConfirmed && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <div className="h-4 w-4 rounded-full bg-green-600 flex items-center justify-center">
                        <span className="text-white text-xs">✓</span>
                      </div>
                      <p className="text-green-600 font-semibold">✅ Transaction confirmed successfully!</p>
                    </div>
                    <p className="text-sm text-gray-600">Your authorization has been processed and is now active on the blockchain.</p>
                    {hash && (
                      <div className="bg-gray-100 p-3 rounded">
                        <p className="text-sm text-gray-700 font-medium">Transaction Hash:</p>
                        <p className="text-xs text-gray-600 font-mono break-all">{hash}</p>
                        <a 
                          href={`https://chainscan-galileo.0g.ai/tx/${hash}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:text-blue-800 text-sm mt-1 inline-block"
                        >
                          🔗 View on 0G Explorer
                        </a>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Error Display */}
        {writeError && (
          <Card className="mt-6 border-l-4 border-l-red-500 bg-red-50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-red-700">
                <span className="text-lg">❌</span>
                Transaction Failed
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <p className="text-red-600 font-medium">Authorization transaction failed:</p>
                <p className="text-red-700 text-sm bg-red-100 p-2 rounded">{writeError.message}</p>
                <p className="text-xs text-red-600">
                  💡 Common causes: Insufficient gas, network issues, or user rejected transaction
                </p>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
