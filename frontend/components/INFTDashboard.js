'use client'

import React, { useState } from 'react'
import { useAccount, useConnect, useDisconnect } from 'wagmi'
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

/**
 * Main INFT Dashboard Component
 * Provides UI for all INFT operations: mint, authorize, infer, transfer
 */
export default function INFTDashboard() {
  const { address, isConnected } = useAccount()
  const { connect, connectors } = useConnect()
  const { disconnect } = useDisconnect()
  
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
    tokenId: '1',
    input: ''
  })
  
  const [transferForm, setTransferForm] = useState({
    from: '',
    to: '',
    tokenId: '1'
  })

  const [inferenceResult, setInferenceResult] = useState(null)
  const [isInferring, setIsInferring] = useState(false)

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
    if (!mintForm.recipient || !mintForm.encryptedURI || !mintForm.metadataHash) {
      alert('Please fill all fields')
      return
    }
    
    try {
      await mintINFT(
        mintForm.recipient,
        mintForm.encryptedURI,
        mintForm.metadataHash
      )
    } catch (error) {
      console.error('Mint failed:', error)
      alert('Mint failed: ' + error.message)
    }
  }

  // Handle authorize usage
  const handleAuthorize = async (e) => {
    e.preventDefault()
    if (!authorizeForm.tokenId || !authorizeForm.userAddress) {
      alert('Please fill all fields')
      return
    }
    
    try {
      await authorizeUsage(authorizeForm.tokenId, authorizeForm.userAddress)
    } catch (error) {
      console.error('Authorize failed:', error)
      alert('Authorize failed: ' + error.message)
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
        </div>

        {/* Transaction Status */}
        {(isWritePending || isConfirming || isConfirmed) && (
          <Card className="mt-6">
            <CardContent className="p-6">
              <div className="flex items-center gap-2">
                {isWritePending && <p>Transaction pending...</p>}
                {isConfirming && <p>Waiting for confirmation...</p>}
                {isConfirmed && (
                  <div>
                    <p className="text-green-600 font-semibold">Transaction confirmed!</p>
                    {hash && (
                      <p className="text-sm text-gray-500 mt-1">
                        Hash: {hash}
                      </p>
                    )}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Error Display */}
        {writeError && (
          <Card className="mt-6 border-red-200 bg-red-50">
            <CardContent className="p-6">
              <p className="text-red-600 font-semibold">Transaction Error:</p>
              <p className="text-red-500 text-sm mt-1">{writeError.message}</p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
