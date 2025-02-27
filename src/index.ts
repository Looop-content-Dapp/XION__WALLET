import express from "express";
import { connectToDatabase } from "./db";
import helmet from "helmet";
// import rateLimit from "express-rate-limit";
import router from "./api/walletApi";

const app = express();

// Basic rate limiting to prevent DoS attacks
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 100 // limit each IP to 100 requests per windowMs
// });

// app.use(limiter);
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

    // Graceful shutdown
    // process.on('SIGTERM', () => {
    //   console.log('SIGTERM signal received: closing HTTP server');
    //   server.close(() => {
    //     console.log('HTTP server closed');
    //     process.exit(0);
    //   });
    // });
  } catch (error) {
    console.error("Failed to start server:", error);
    // process.exit(1);
  }
}

startServer();
