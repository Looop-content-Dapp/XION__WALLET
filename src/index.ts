import express from "express";
import { connectToDatabase } from "./db";
import helmet from "helmet";
import router from "./api/walletApi";

const app = express();

app.use(express.json({ limit: "10mb" })); // Limit payload size
app.use(helmet());
app.use("/api/wallet", router);

const PORT = process.env.PORT || 3001;

async function startServer() {
  try {
    await connectToDatabase();
    const server = app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });

  } catch (error) {
    console.error("Failed to start server:", error);

  }
}

startServer();
