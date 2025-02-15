# XION Wallet SDK

A TypeScript SDK for interacting with the XION blockchain network, providing secure wallet management and transaction capabilities.

## Prerequisites
- Node.js >= 16.0.0
- TypeScript >= 4.5.0
- Access to XION blockchain network (testnet or mainnet)

## Installation
```bash
npm install xion_test
```

## Configuration
Create a `.env` file in your project root:

```
RPC_URL=https://rpc.xion-testnet-1.burnt.com:443
REST_URL=https://api.xion-testnet-1.burnt.com
CALLBACK_URL=http://localhost:3000/callback
TREASURY_ADDRESS=xion1...
PORT=3000
```

## Features
- Secure wallet creation and management
- Transaction signing and verification
- Grant management system
- Biometric authentication support
- Encrypted storage capabilities

## Security Considerations
- **Key Storage:** All sensitive data is encrypted before storage
- **Biometric Authentication:** Implements secure session management
- **Grant Expiration:** Automatically validates grant expiration
- **Backup Encryption:** Uses strong encryption for wallet backups

## Development
```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Run tests
npm run test

# Run tests with coverage
npm run test:coverage
```

## Project Structure
```
src/
├── AbstraxionAuth.ts        # Authentication management
├── GranteeSignerClient.ts   # Client for grant signing
├── SignArbSecp256k1HdWallet.ts # Wallet implementation
├── api/                     # API endpoints
├── config.ts                # Configuration management
├── types/                   # TypeScript type definitions
└── index.ts                 # Main entry point
```

## Testing
The project uses Jest for testing. Tests can be run with:

```bash
npm test
```

For watching mode:

```bash
npm run test:watch
```

## License
This project is licensed under the ISC License - see the LICENSE file for details.

## Support
For support, please open an issue in the GitHub repository or contact the maintainers.

