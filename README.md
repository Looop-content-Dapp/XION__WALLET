
# Xion Wallet API

Welcome to the **Looop Music Wallet API**, a Node.js-based backend for a cryptocurrency wallet designed for music lovers and artists on the Xion blockchain (a Cosmos SDK-based chain). This project leverages CosmJS and `@burnt-labs` packages to provide a seamless, Web2-like experience while maintaining blockchain security. It ties wallet functionality to user email/password logins, encrypts mnemonics server-side, and offers Web2-style recovery, making it ideal for a music-focused audience.

---

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Why This Works for Looop Music](#why-this-works-for-looop-music)
- [Project Structure](#project-structure)
- [Setup](#setup)
- [API Endpoints](#api-endpoints)
- [How It Works](#how-it-works)
- [Security](#security)
- [Development](#development)
- [Future Improvements](#future-improvements)
- [License](#license)

---

## Overview
The Looop Music Wallet API provides a backend for managing Xion wallets tied to user accounts in a MongoDB database. Unlike traditional crypto wallets that burden users with mnemonic phrases, this project mimics a Web2 experience:
- Users sign up and log in with email/password.
- Mnemonics are auto-generated, encrypted, and stored server-side, secured by a password-derived key and a server secret.
- Recovery mimics Web2 "forgot password" flows via email tokens.
- Optional mnemonic export is available for advanced users (e.g., artists).

This hybrid custodial/non-custodial approach balances usability for music fans with flexibility for artists, aligning with the Looop Music vision of bridging music and blockchain.

---

## Features
- **Web2-Like UX**: Email/password login, no mnemonic exposure by default.
- **Wallet Management**: Auto-generates Xion wallets, ties them to user emails.
- **Secure Mnemonic Storage**: Encrypts mnemonics with AES-256-CBC using password + server secret.
- **Recovery**: Web2-style password reset via email tokens, re-encrypting mnemonics.
- **Transactions**: Supports token transfers on Xion using CosmJS and `@burnt-labs` signers.
- **MongoDB Integration**: Persistent storage for user profiles and wallet data.
- **Music-Themed**: Customizable UX prompts (e.g., “Your Music Wallet”).

---

## Why This Works for Looop Music
- **Music Lovers**: 
  - Non-technical users expect a simple login like Spotify or SoundCloud. This API hides blockchain complexity, requiring only email/password.
  - Seamless token transfers (e.g., buying music NFTs) feel like in-app purchases.
- **Artists**: 
  - Optional mnemonic export supports those needing full control (e.g., managing royalty tokens or NFTs).
  - Secure storage protects valuable assets without manual backup hassles.
- **Web2 Familiarity**: 
  - Recovery via email aligns with users’ mental models, reducing support overhead.
  - Music-themed prompts (e.g., “Log in to your Music Vault!”) enhance engagement.
- **Xion Compatibility**: 
  - Built with CosmJS and `@burnt-labs` for Xion, ensuring native blockchain support.

This approach makes blockchain accessible to your audience while preserving security and flexibility.

---

## Project Structure
```
XION__WALLET/
├── db.ts               # MongoDB connection setup
├── models/
│   └── User.ts         # Mongoose User schema with wallet fields
├── AbstraxionAuth.ts   # Core wallet logic (signup, login, recovery, transactions)
├── walletRouter.ts     # Express API routes
├── server.ts           # Server entry point
├── .env                # Environment variables (MongoDB URI, secrets)
├── package.json        # Dependencies and scripts
└── README.md           # This file
```

---

## Setup

### Prerequisites
- Node.js (v16+)
- MongoDB (using provided URI or local instance)
- Xion Testnet access (RPC/REST URLs)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/XION__WALLET.git
   cd XION__WALLET
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file:
   ```
   MONGODB_URI=mongodb+srv://looopMusic:Dailyblessing@looopmusic.a5lp1.mongodb.net/?retryWrites=true&w=majority&appName=LooopMusic
   SERVER_SECRET=your-very-long-random-secret
   RPC_URL=https://rpc.xion-testnet-1.burnt.com:443
   REST_URL=https://api.xion-testnet-1.burnt.com
   TREASURY_ADDRESS=your-treasury-address
   GRANTER_ADDRESS=your-granter-address
   PORT=3001
   ```
4. Run the server:
   ```bash
   npm run start  # Assumes "start": "ts-node server.ts" in package.json
   ```

### Dependencies
- `express`: Web server
- `mongoose`: MongoDB ORM
- `@cosmjs/*`: Blockchain interaction
- `@burnt-labs/constants`: Xion constants
- `bcrypt`: Password hashing
- `dotenv`: Environment variables
- `typescript`, `ts-node`: TypeScript support

---

## API Endpoints

| Endpoint            | Method | Description                          | Request Body                          | Response                              |
|---------------------|--------|--------------------------------------|---------------------------------------|---------------------------------------|
| `/api/wallet/signup`| POST   | Creates a new user and wallet        | `{ email, password }`                | `{ walletAddress, mnemonic?, ... }`   |
| `/api/wallet/login` | POST   | Logs in and loads wallet             | `{ email, password }`                | `{ walletAddress, isAuthenticated }`  |
| `/api/wallet/recover`| POST   | Requests password recovery          | `{ email }`                          | `{ recoveryToken }` (emailed in prod) |
| `/api/wallet/reset-password`| POST | Resets password with token  | `{ email, token, newPassword }`      | `{ success, message }`                |
| `/api/wallet/transfer`| POST | Transfers tokens on Xion            | `{ email, password, toAddress, amount }` | `{ transactionHash, ... }`         |
| `/api/wallet/balance/:address`| GET | Gets Xion balance           | None (param: `address`)              | `{ address, balance, denom }`         |

---

## How It Works

### Core Components
- **`AbstraxionAuth.ts`**:
  - **Signup**: Generates a 24-word mnemonic, encrypts it with `password + SERVER_SECRET`, hashes the password with bcrypt, and stores in MongoDB.
  - **Login**: Verifies password, decrypts mnemonic, loads wallet into memory for transactions.
  - **Recovery**: Issues a token, emailed to user; reset re-encrypts mnemonic with new password.
  - **Transactions**: Uses `GranteeSignerClient` for Xion token transfers.

- **`walletRouter.ts`**:
  - Exposes RESTful endpoints for wallet operations.
  - Integrates with `AbstraxionAuth` for logic.

- **`User.ts`**:
  - MongoDB schema with `wallets.xion` storing encrypted mnemonic, IV, salt, and address.

### Flow Diagram
```
[Signup]
User → Email/Password → Server: Generate Mnemonic → Encrypt → Store in MongoDB → Return Address

[Login]
User → Email/Password → Server: Verify Password → Decrypt Mnemonic → Load Wallet → Enable Transactions

[Recovery]
User → Email → Server: Send Token → User: Reset Password → Re-encrypt Mnemonic

[Transfer]
User → Email/Password/ToAddress/Amount → Server: Login → Sign & Broadcast → Return Tx Hash
```

### Mnemonic Security
- **Encryption**: AES-256-CBC with a key from `password + SERVER_SECRET`, ensuring server cooperation is needed to decrypt.
- **No Exposure**: Users don’t see mnemonics unless they opt to export during signup.
- **Recovery**: Web2-style email reset re-encrypts the mnemonic, no manual backup needed.
- **Export Option**: Advanced users can save mnemonics offline (e.g., artists securing NFT assets).

---

## Security
- **Password Hashing**: Bcrypt with 12 rounds secures user passwords.
- **Mnemonic Encryption**: AES-256-CBC with unique IV/salt per user, tied to server secret.
- **Recovery Tokens**: Time-limited (24h) tokens prevent unauthorized resets.
- **Server Secret**: Ensures mnemonics can’t be decrypted without server access, adding a layer beyond user password.
- **HTTPS**: Required in production to secure API calls.
- **Trade-Off**: Semi-custodial—server stores encrypted mnemonics, mitigated by export option.

---

## Development

### Running Locally
1. Start MongoDB (if local) or use the provided URI.
2. Install dependencies: `npm install`.
3. Run: `npm run start`.

### Testing
- **Signup**: `curl -X POST http://localhost:3001/api/wallet/signup -d '{"email":"fan@music.com","password":"PurpleRain1984!"}'`
- **Login**: `curl -X POST http://localhost:3001/api/wallet/login -d '{"email":"fan@music.com","password":"PurpleRain1984!"}'`
- **Recover**: `curl -X POST http://localhost:3001/api/wallet/recover -d '{"email":"fan@music.com"}'`
- **Reset**: `curl -X POST http://localhost:3001/api/wallet/reset-password -d '{"email":"fan@music.com","token":"returned-token","newPassword":"NewTune2023!"}'`
- **Transfer**: `curl -X POST http://localhost:3001/api/wallet/transfer -d '{"email":"fan@music.com","password":"PurpleRain1984!","toAddress":"xion1anotheraddress","amount":"1000000"}'`

### Adding Email Service
For production recovery, integrate Nodemailer:
```typescript
import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

async function sendRecoveryEmail(email: string, token: string) {
  await transporter.sendMail({
    from: 'Looop Music <no-reply@looopmusic.com>',
    to: email,
    subject: 'Reset Your Music Wallet Password',
    text: `Click to reset: http://yourapp.com/reset?token=${token}`
  });
}
```

---

## Future Improvements
- **Email Verification**: Add OTP on signup for extra security.
- **2FA**: Implement TOTP (e.g., Google Authenticator) for artists.
- **Caching**: Use Redis for frequent wallet lookups.
- **Session Management**: Add JWT tokens for persistent logins.
- **Music UX**: Fully theme responses (e.g., “Your wallet is tuned up!”).
- **Non-Custodial Mode**: Offer a toggle for users to manage mnemonics entirely client-side.

---

## License
MIT License - feel free to adapt and extend for Looop Music!

---