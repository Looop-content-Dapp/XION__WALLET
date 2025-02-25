import { Router, Request, Response, NextFunction } from 'express';
import { AbstraxionAuth } from '../AbstraxionAuth';
import dotenv from 'dotenv';
import { coins } from "@cosmjs/amino";
import { CosmWasmClient } from '@cosmjs/cosmwasm-stargate';
import { connectToDatabase } from '../db';
import rateLimit from 'express-rate-limit'

dotenv.config();
const router = Router();
const auth = new AbstraxionAuth();

connectToDatabase();

auth.configureAbstraxionInstance(
  process.env.RPC_URL || 'https://rpc.xion-testnet-1.burnt.com:443',
  process.env.REST_URL || 'https://api.xion-testnet-1.burnt.com',
  process.env.TREASURY_ADDRESS
);

// Define rate limiter (100 requests per 15 minutes per IP)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { success: false, message: 'Too many requests from this IP, please try again later.' }
});

// Apply rate limiter to all routes
router.use(limiter);

const asyncHandler = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void | Response>
) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

router.post('/signup', asyncHandler(async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password required' });
  }

  const { address, mnemonic } = await auth.signup(email, password);
  return res.status(200).json({
    success: true,
    data: { walletAddress: address, mnemonic }, // Optional: include mnemonic
    message: 'Account created successfully - save your mnemonic if desired!'
  });
}));

router.post('/login', asyncHandler(async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password required' });
  }

  await auth.login(email, password);
  const walletAddress = await auth.getKeypairAddress();
  return res.status(200).json({
    success: true,
    data: { walletAddress  },
    message: 'Logged in successfully'
  });
}));

// Endpoint to get NFTs for the logged-in user
router.post('/nfts', asyncHandler(async (req: Request, res: Response) => {
  const { email, password, contractAddress } = req.body;
  if (!email || !password || !contractAddress) {
    return res.status(400).json({
      success: false,
      message: 'Email, password, and contractAddress are required',
    });
  }

  // Authenticate the user
  await auth.login(email, password);
  const nfts = await auth.getLoggedInUserNFTs(contractAddress);

  return res.status(200).json({
    success: true,
    data: {
      walletAddress: await auth.getKeypairAddress(),
      contractAddress,
      nfts,
    },
    message: 'NFTs retrieved successfully',
  });
}));

// Endpoint to get NFTs for any address (public query)
router.get('/nfts/:address', asyncHandler(async (req: Request, res: Response) => {
  const { address } = req.params;
  const { contractAddress } = req.query; // Pass contractAddress as a query parameter
  if (!address || !contractAddress) {
    return res.status(400).json({
      success: false,
      message: 'Wallet address and contractAddress are required',
    });
  }

  const nfts = await auth.getNFTsForAddress(address, contractAddress as string);

  return res.status(200).json({
    success: true,
    data: {
      walletAddress: address,
      contractAddress,
      nfts,
    },
    message: 'NFTs retrieved successfully',
  });
}));

router.post('/recover', asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: 'Email required' });
  }

  const token = await auth.requestRecovery(email);
  return res.status(200).json({
    success: true,
    data: { recoveryToken: token }, // In prod, email this
    message: 'Recovery email sent - check your inbox!'
  });
}));

router.post('/reset-password', asyncHandler(async (req: Request, res: Response) => {
  const { email, token, newPassword } = req.body;
  if (!email || !token || !newPassword) {
    return res.status(400).json({ success: false, message: 'Email, token, and new password required' });
  }

  await auth.resetPassword(email, token, newPassword);
  return res.status(200).json({
    success: true,
    message: 'Password reset successfully - log in with your new password'
  });
}));

router.post('/transfer', asyncHandler(async (req: Request, res: Response) => {
  const { email, password, toAddress, amount } = req.body;
  if (!email || !password || !toAddress || !amount) {
    return res.status(400).json({ success: false, message: 'Missing required parameters' });
  }

  await auth.login(email, password);
  const signerClient = await auth.getSigner();
  const fromAddress = await auth.getKeypairAddress();
  const usdcDenom = 'ibc/57097251ED81A232CE3C9D899E7C8096D6D87EF84BA203E12E424AA4C9B57A64';

  const balance = await signerClient.getBalance(fromAddress, usdcDenom);
  if (BigInt(balance.amount) < BigInt(amount)) {
    return res.status(400).json({ success: false, message: 'Insufficient balance' });
  }

  const result = await signerClient.sendTokens(
    fromAddress,
    toAddress,
    coins(amount, usdcDenom),
    { amount: coins(1, usdcDenom), gas: "200000" }
  );

  return res.status(200).json({
    success: true,
    data: { transactionHash: result.transactionHash, fromAddress, toAddress, amount, denom: usdcDenom },
    message: 'Transfer completed successfully'
  });
}));

router.get('/balance/:address', asyncHandler(async (req: Request, res: Response) => {
  const { address } = req.params;
  const client = await CosmWasmClient.connect(process.env.RPC_URL || 'https://rpc.xion-testnet-1.burnt.com:443');
  const balance = await client.getBalance(address, 'ibc/57097251ED81A232CE3C9D899E7C8096D6D87EF84BA203E12E424AA4C9B57A64');

  return res.status(200).json({
    success: true,
    data: { address, balance: balance.amount, denom: balance.denom },
    message: 'Balance retrieved successfully'
  });
}));

router.post('/execute-contract', asyncHandler(async (req: Request, res: Response) => {
  const { email, password, contractAddress, msg, memo } = req.body;
  if (!email || !password || !contractAddress || !msg) {
    return res.status(400).json({ success: false, message: 'Missing required parameters: email, password, contractAddress, and msg are required' });
  }

  await auth.login(email, password); // Authenticate user
  const result = await auth.executeSmartContract(contractAddress, msg, memo);

  return res.status(200).json({
    success: true,
    data: result,
    message: 'Smart contract executed successfully'
  });
}));

router.post('/reset-email', asyncHandler(async (req: Request, res: Response) => {
  const { currentEmail, newEmail, password } = req.body;
  if (!currentEmail || !newEmail || !password) {
    return res.status(400).json({ success: false, message: 'Missing required parameters: currentEmail, newEmail, and password are required' });
  }

  const result = await auth.resetEmail(currentEmail, newEmail, password);

  return res.status(200).json({
    success: true,
    data: result,
    message: 'Email reset successfully'
  });
}));

export default router;