import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

export const config = {
  rpcUrl: process.env.RPC_URL || 'https://rpc.xion-testnet-2.burnt.com:443',
  restUrl: process.env.REST_URL || 'https://api.xion-testnet-2.burnt.com',
  callbackUrl: process.env.CALLBACK_URL || 'http://localhost:3000/callback',
  treasuryAddress: process.env.TREASURY_ADDRESS || 'xion1...',
  port: process.env.PORT ? parseInt(process.env.PORT) : 3000,
  storageDir: process.env.STORAGE_DIR || path.join(__dirname, '../storage')
};
