import express from 'express';
import { connectToDatabase } from "./db"
import helmet from 'helmet';
import router from '../src/api/walletApi'

const app = express();

app.use(express.json());
app.use(helmet());
app.use('/api/wallet', router);

const PORT = process.env.PORT || 3001;

async function startServer() {
  await connectToDatabase();
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
}

startServer();