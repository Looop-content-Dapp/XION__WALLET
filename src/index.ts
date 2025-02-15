import express from 'express';
import walletRouter from './api/walletApi';

const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Mount the wallet routes with the /api/wallet prefix
app.use('/api/wallet', walletRouter);

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});