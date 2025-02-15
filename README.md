# XION Test SDK

A TypeScript SDK for interacting with the XION blockchain, providing authentication, wallet management, and transaction capabilities.

## Features

- Wallet creation and management
- Authentication flow with grant-based permissions
- Biometric authentication support
- Transaction execution
- Key management and backup
- Grant polling and validation
- Subscription-based auth state management

## Installation

```bash
npm install xion_test
```

## Prerequisites
- **Node.js** >= 16.0.0
- **TypeScript** >= 4.5.0
- **Access to XION blockchain network** (testnet or mainnet)

## Configuration

Create a `.env` file in your project root:

```env
RPC_URL=https://rpc.xion-testnet-1.burnt.com:443
REST_URL=https://api.xion-testnet-1.burnt.com
CALLBACK_URL=http://localhost:3000/callback
TREASURY_ADDRESS=xion1...
PORT=3000
```

## Basic Usage

### Initialize Authentication

```typescript
import { AbstraxionAuth } from 'xion_test';

const auth = new AbstraxionAuth();

// Configure the instance
auth.configureAbstraxionInstance(
  "https://rpc.xion-testnet-1.burnt.com:443",
  "https://api.xion-testnet-1.burnt.com",
  [], // grantContracts
  false, // stake
  [], // bank
  "http://localhost:3000/callback", // callbackUrl
  "xion1..." // treasury address
);
```

## Authentication Flow

- **Login**: `auth.login()`
- **Logout**: `auth.logout()`
- **Authenticate**: `auth.authenticate()`

## Execute Transactions

The SDK supports executing transactions securely using `getSigner()` method.

## Wallet Management

Manage and interact with user wallets within the XION ecosystem.

## Advanced Features

### Grant Management

The SDK supports grant-based permissions for contract interactions.

### Biometric Authentication

- Implements **secure session management**
- Ensures **strong encryption** for sensitive data

## Security Considerations

- **Key Storage**: All sensitive data is encrypted before storage
- **Biometric Authentication**: Implements secure session management
- **Grant Expiration**: Automatically validates grant expiration
- **Backup Encryption**: Uses strong encryption for wallet backups

## Development

### API Documentation

#### `AbstraxionAuth` Class

The main class for handling authentication and wallet management.

##### Methods
- `configureAbstraxionInstance(rpc, restUrl?, grantContracts?, stake?, bank?, callbackUrl?, treasury?)`: Configure the instance
- `login()`: Initiate login flow
- `logout()`: Clear authentication state
- `authenticate()`: Verify authentication status
- `getSigner()`: Get `GranteeSignerClient` instance
- `subscribeToAuthStateChange(callback)`: Subscribe to auth state changes

### Services

- **KeyManagementService**: Handles key encryption and backup
- **BiometricAuthService**: Manages biometric authentication
- **WalletAbstractionService**: Creates and manages wallets

## Contributing

1. Fork the repository
2. Create your feature branch:
   ```sh
   git checkout -b feature/amazing-feature
   ```
3. Commit your changes:
   ```sh
   git commit -m 'Add amazing feature'
   ```
4. Push to the branch:
   ```sh
   git push origin feature/amazing-feature
   ```
5. Open a Pull Request

## License

This project is licensed under the **ISC License** - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.

# XION__WALLET
# XION__WALLET
