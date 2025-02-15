import { Router, Request, Response, RequestHandler } from 'express';
import { AbstraxionAuth } from '../AbstraxionAuth';
import dotenv from 'dotenv';
import { coins } from "@cosmjs/amino";
import { CosmWasmClient, SigningCosmWasmClient } from '@cosmjs/cosmwasm-stargate';
import { OfflineSigner } from '@cosmjs/proto-signing';

dotenv.config();

const router = Router();
const auth = new AbstraxionAuth();

// Initialize AbstraxionAuth with configuration
auth.configureAbstraxionInstance(
  process.env.RPC_URL || 'https://rpc.xion-testnet-1.burnt.com:443',
  process.env.REST_URL || 'https://api.xion-testnet-1.burnt.com',
  [], // grantContracts
  false, // stake
  [], // bank
  process.env.CALLBACK_URL || 'http://localhost:3000/callback',
  process.env.TREASURY_ADDRESS
);

// Add proper type definitions for the request
interface CreateWalletRequest {
  email: string;
  emailToken: string;
}

// Fix the create-wallet route handler
router.post('/create-wallet', (async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    
    // Verify email authentication
    const isVerified = await auth.verifyIdentity('email', { email });
    if (!isVerified) {
      return res.status(401).json({
        success: false,
        message: 'Email verification failed'
      });
    }

    // Initialize login process which creates a new wallet
    await auth.login();

    // Get the wallet address
    const walletAddress = await auth.getKeypairAddress();

    // Get signer for additional wallet operations
    // const signer = await auth.getSigner();

    return res.status(200).json({
      success: true,
      data: {
        walletAddress,
        isAuthenticated: auth.isLoggedIn,
      },
      message: 'Wallet created successfully'
    });
  } catch (error: any) {
    console.error('Wallet creation failed:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Failed to create wallet'
    });
  }
}) as unknown as RequestHandler);

// Modify the balance endpoint to accept email in query params
router.get('/balance/:address', (async (req: Request, res: Response) => {
  try {
    const { address } = req.params;
    
    // Create CosmWasm client
    const client = await CosmWasmClient.connect(process.env.RPC_URL || 'https://rpc.xion-testnet-1.burnt.com:443');
    
    // Query XION balance for the address
    const balance = await client.getBalance(address, 'ibc/57097251ED81A232CE3C9D899E7C8096D6D87EF84BA203E12E424AA4C9B57A64');
    console.log('Balance:', balance);

    return res.status(200).json({
      success: true,
      data: {
        address,
        balance: balance.amount,
        denom: balance.denom
      },
      message: 'Balance retrieved successfully'
    });

  } catch (error: any) {
    console.error('Failed to get balance:', error);
    return res.status(500).json({
      success: false,
      message: `Failed to get balance: ${error.message}`
    });
  }
}) as unknown as RequestHandler);

// Add the transfer endpoint
router.post('/transfer', (async (req: Request, res: Response) => {
  try {
    const { fromAddress, toAddress, amount } = req.body;

    if (!fromAddress || !toAddress || !amount) {
      return res.status(400).json({
        success: false,
        message: 'Missing required parameters: fromAddress, toAddress, or amount'
      });
    }

    // Get existing keypair first
    const keypair = await auth.getLocalKeypair();
    if (!keypair) {
      return res.status(401).json({
        success: false,
        message: 'No wallet found. Please create a wallet first.'
      });
    }

    // Set the abstract account and authenticate
    auth.abstractAccount = keypair;
    await auth.login();

    // Get the signer client
    const signerClient = await auth.getSigner();
    
    const usdcDenom = 'ibc/57097251ED81A232CE3C9D899E7C8096D6D87EF84BA203E12E424AA4C9B57A64';

    // Check balance before proceeding
    const balance = await signerClient.getBalance(fromAddress, usdcDenom);
    if (BigInt(balance.amount) < BigInt(amount)) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient balance'
      });
    }

    // Execute transfer using the signer client directly
    const result = await signerClient.sendTokens(
      fromAddress,
      toAddress,
      coins(amount, usdcDenom),
      {
        amount: coins(1, usdcDenom),
        gas: "200000",
      }
    );

    return res.status(200).json({
      success: true,
      data: {
        transactionHash: result.transactionHash,
        fromAddress,
        toAddress,
        amount,
        denom: usdcDenom
      },
      message: 'Transfer completed successfully'
    });

  } catch (error: any) {
    console.error('Transfer failed:', error);
    return res.status(500).json({
      success: false,
      message: `Transfer failed: ${error.message}`
    });
  }
}) as unknown as RequestHandler);

// Add this new route handler
router.get('/wallet/:email', (async (req: Request, res: Response) => {
  try {
    const { email } = req.params;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email parameter is required'
      });
    }

    // Verify email authentication first
    const isVerified = await auth.verifyIdentity('email', { email });
    if (!isVerified) {
      return res.status(401).json({
        success: false,
        message: 'Email verification failed'
      });
    }

    // Retrieve wallet by email
    const wallet = await auth.getWalletByEmail(email);
    
    if (!wallet) {
      return res.status(404).json({
        success: false,
        message: 'No wallet found for this email'
      });
    }

    // Get the wallet address
    const accounts = await wallet.getAccounts();
    const walletAddress = accounts[0].address;

    return res.status(200).json({
      success: true,
      data: {
        email,
        walletAddress,
        isAuthenticated: true
      },
      message: 'Wallet retrieved successfully'
    });

  } catch (error: any) {
    console.error('Failed to retrieve wallet:', error);
    return res.status(500).json({
      success: false,
      message: `Failed to retrieve wallet: ${error.message}`
    });
  }
}) as unknown as RequestHandler);

export default router;