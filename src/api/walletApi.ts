import { Router, Request, Response, NextFunction } from 'express';
import { AbstraxionAuth } from '../AbstraxionAuth';
import dotenv from 'dotenv';
import { coins } from "@cosmjs/amino";
import { CosmWasmClient } from '@cosmjs/cosmwasm-stargate';
import { connectToDatabase } from '../db';
// import rateLimit from 'express-rate-limit'

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
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 100, // Limit each IP to 100 requests per windowMs
//   message: { success: false, message: 'Too many requests from this IP, please try again later.' }
// });

// Apply rate limiter to all routes
// router.use(limiter);

const asyncHandler = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void | Response>
) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

router.post('/signup', asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: 'Email required' });
  }

  const { address, mnemonic } = await auth.signup(email);
  return res.status(200).json({
    success: true,
    data: { walletAddress: address, mnemonic },
    message: 'Account created successfully - save your mnemonic if desired!'
  });
}));

router.post('/login', asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: 'Email required' });
  }

  await auth.login(email);
  const walletAddress = await auth.getKeypairAddress();
  return res.status(200).json({
    success: true,
    data: { walletAddress },
    message: 'Logged in successfully'
  });
}));

router.post('/nfts', asyncHandler(async (req: Request, res: Response) => {
  const { email, contractAddress } = req.body;
  if (!email || !contractAddress) {
    return res.status(400).json({
      success: false,
      message: 'Email and contractAddress are required',
    });
  }

  await auth.login(email);
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

router.get('/nfts/:address', asyncHandler(async (req: Request, res: Response) => {
  const { address } = req.params;
  const { contractAddress } = req.query;
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

router.post('/transfer', asyncHandler(async (req: Request, res: Response) => {
  const { email, toAddress, amount } = req.body;
  if (!email || !toAddress || !amount) {
    return res.status(400).json({ success: false, message: 'Missing required parameters' });
  }

  await auth.login(email);
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

router.post('/balances', asyncHandler(async (req: Request, res: Response) => {
    const { email, denoms } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email required' });
    }

    await auth.login(email);
    const address = await auth.getKeypairAddress();
    const balances = await auth.getBalances(address, denoms);

    return res.status(200).json({
      success: true,
      data: { address, balances },
      message: 'Balances retrieved successfully'
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
  const { email, contractAddress, msg, memo } = req.body;
  if (!email || !contractAddress || !msg) {
    return res.status(400).json({ success: false, message: 'Missing required parameters: email, contractAddress, and msg are required' });
  }

  await auth.login(email);
  const result = await auth.executeSmartContract(contractAddress, msg, memo);

  return res.status(200).json({
    success: true,
    data: result,
    message: 'Smart contract executed successfully'
  });
}));

router.post('/reset-email', asyncHandler(async (req: Request, res: Response) => {
  const { currentEmail, newEmail } = req.body;
  if (!currentEmail || !newEmail) {
    return res.status(400).json({ success: false, message: 'Missing required parameters: currentEmail and newEmail are required' });
  }

  const result = await auth.resetEmail(currentEmail, newEmail);

  return res.status(200).json({
    success: true,
    data: result,
    message: 'Email reset successfully'
  });
}));

export default router;
