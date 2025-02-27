import { GasPrice, SigningStargateClient, calculateFee, coins, Coin  } from "@cosmjs/stargate";
import { fetchConfig } from "@burnt-labs/constants";
import { makeCosmoshubPath } from "@cosmjs/amino";
import { GranteeSignerClient } from "./GranteeSignerClient";
import { SignArbSecp256k1HdWallet } from "./SignArbSecp256k1HdWallet";
import * as crypto from "crypto";
import { Wallet } from "./models/Wallet";
import bcrypt from 'bcrypt';
import { Bip39 } from "@cosmjs/crypto";
import { MsgGrantAllowance } from "cosmjs-types/cosmos/feegrant/v1beta1/tx";
import { Any } from "cosmjs-types/google/protobuf/any";
import { BasicAllowance } from "cosmjs-types/cosmos/feegrant/v1beta1/feegrant";
import { Registry } from "@cosmjs/proto-signing/build";
import { CosmWasmClient } from "@cosmjs/cosmwasm-stargate/build";

/**
 * Interface representing a fee grant configuration response from the Xion network.
 */
interface GrantsResponse {
  readonly grants: readonly Grant[];
  readonly pagination: Pagination;
}

/**
 * Interface representing a single fee grant.
 */
interface Grant {
  readonly granter: string;
  readonly grantee: string;
  readonly authorization: Authorization;
  readonly expiration: string | null;
}

/**
 * Interface representing the authorization details of a grant.
 */
interface Authorization {
  readonly "@type": string;
  readonly grants: readonly GrantAuthorization[];
}

/**
 * Interface representing grant authorization details.
 */
interface GrantAuthorization {
  readonly contract: string;
  readonly limit: Limit;
  readonly filter: Filter;
}

/**
 * Interface representing the limit of a grant authorization.
 */
interface Limit {
  readonly "@type": string;
  readonly remaining: string;
}

/**
 * Interface representing the filter of a grant authorization.
 */
interface Filter {
  readonly "@type": string;
}

/**
 * Interface representing pagination metadata for API responses.
 */
interface Pagination {
  readonly next_key: string | null;
  readonly total: string;
}

/**
 * Manages authentication, wallet operations, and smart contract interactions for Xion wallets.
 * Provides methods for user signup, login, fee grants, and smart contract execution.
 */
export class AbstraxionAuth {
  private rpcUrl?: string;
  private restUrl?: string;
  private treasury?: string;
  private readonly serverSecret: string;
  private client?: GranteeSignerClient;
  private abstractAccount?: SignArbSecp256k1HdWallet;
  private isLoggedIn: boolean = false;
  private readonly authStateChangeSubscribers: ((isLoggedIn: boolean) => void)[] = [];

  /**
   * Creates an instance of AbstraxionAuth.
   * @throws {Error} If SERVER_SECRET is not provided in the environment.
   */
  constructor() {
    this.serverSecret = process.env.SERVER_SECRET || (() => { throw new Error('SERVER_SECRET is required in .env'); })();
    console.log('Initialized with Server Secret:', this.serverSecret);
  }

  /**
   * Configures the Xion instance with RPC, REST, and treasury addresses.
   * @param rpc The RPC endpoint URL.
   * @param restUrl Optional REST endpoint URL.
   * @param treasury Optional treasury address.
   */
  configureAbstraxionInstance(rpc: string, restUrl?: string, treasury?: string): void {
    this.rpcUrl = rpc;
    this.restUrl = restUrl;
    this.treasury = treasury;
  }

  /**
   * Subscribes to authentication state changes.
   * @param callback Function to call when auth state changes.
   * @returns Unsubscribe function.
   */
  subscribeToAuthStateChange(callback: (isLoggedIn: boolean) => void): () => void {
    this.authStateChangeSubscribers.push(callback);
    return () => {
      const index = this.authStateChangeSubscribers.indexOf(callback);
      if (index !== -1) this.authStateChangeSubscribers.splice(index, 1);
    };
  }

  private triggerAuthStateChange(isLoggedIn: boolean): void {
    this.isLoggedIn = isLoggedIn;
    this.authStateChangeSubscribers.forEach((callback) => callback(isLoggedIn));
  }

  /**
   * Retrieves the granter address from environment variables, validating its format.
   * @returns The granter address starting with "xion1" or undefined if invalid/unset.
   */
  getGranter(): string | undefined {
    const granter = process.env.GRANTER_ADDRESS;
    if (granter && !granter.startsWith("xion1")) {
      console.warn('GRANTER_ADDRESS is invalid; must start with "xion1". Proceeding without granter:', granter);
      return undefined;
    }
    return granter;
  }

  private setGranter(address: string): void {
    // Optionally store in session/db if needed
  }

  private normalizePassword(password: string): string {
    return password.trim();
  }

  private encryptMnemonic(mnemonic: string): { encrypted: string; iv: string; salt: string } {
    console.log('Encrypting with Server Secret:', this.serverSecret);
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(this.serverSecret, salt, 100000, 32, 'sha256');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(mnemonic, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    console.log('Encrypted Data:', { encrypted, iv: iv.toString('hex'), salt: salt.toString('hex') });
    return { encrypted, iv: iv.toString('hex'), salt: salt.toString('hex') };
  }

  private decryptMnemonic(encrypted: string, iv: string, salt: string): string {
    console.log('Decrypting with:', { encrypted, iv, salt, serverSecret: this.serverSecret });
    const saltBuffer = Buffer.from(salt, 'hex');
    const ivBuffer = Buffer.from(iv, 'hex');
    const key = crypto.pbkdf2Sync(this.serverSecret, saltBuffer, 100000, 32, 'sha256');
    console.log('Derived Key:', key.toString('hex'));
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, ivBuffer);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    console.log('Decrypted:', decrypted);
    return decrypted;
  }

  private generateDeterministicMnemonic(email: string): string {
    const seed = crypto.pbkdf2Sync(email, this.serverSecret, 100000, 32, 'sha256');
    return Bip39.encode(seed).toString();
  }

 /**
 * Dispenses test tokens to a new user's address from the treasury account.
 * @param recipientAddress The Xion address to receive test tokens.
 * @param amount The amount of uxion to send (default: 1000000 uxion, i.e., 1 XION).
 * @throws {Error} If treasury mnemonic or RPC URL is not configured.
 */
private async dispenseTestTokens(recipientAddress: string, amount: string = "1000000"): Promise<void> {
  const treasuryMnemonic = process.env.TREASURY_MNEMONIC;
  if (!treasuryMnemonic) {
    console.error("TREASURY_MNEMONIC not set in .env; cannot dispense test tokens");
    return;
  }
  if (!this.rpcUrl) throw new Error("RPC URL must be configured");

  try {
    const treasuryWallet = await SignArbSecp256k1HdWallet.fromMnemonic(treasuryMnemonic, { prefix: "xion" });
    const [treasuryAccount] = await treasuryWallet.getAccounts();
    const treasuryAddress = treasuryAccount.address;

    const client = await GranteeSignerClient.connectWithSigner(this.rpcUrl, treasuryWallet, {
      gasPrice: GasPrice.fromString("0uxion"),
      granteeAddress: treasuryAddress, // Treasury acts as its own grantee
      treasuryAddress: this.treasury,
    });

    const fee = {
      amount: coins(5000, "uxion"), // Small fee for the transaction
      gas: "200000",
    };
    const tokens = coins(amount, "uxion");

    const result = await client.sendTokens(
      treasuryAddress,
      recipientAddress,
      tokens,
      fee,
      "Dispensing test tokens to new user"
    );

    console.log(`Test tokens dispensed to ${recipientAddress}. Tx Hash: ${result.transactionHash}`);
  } catch (error) {
    console.error(`Failed to dispense test tokens to ${recipientAddress}:`, error);
    throw new Error("Token dispensing failed");
  }
}

/**
 * Signs up a new user, creating a wallet, issuing a fee grant, and dispensing test tokens.
 * @param email User's email address.
 * @param password User's password.
 * @returns Object containing the user's address, mnemonic, and optional warnings.
 */
async signup(email: string, password: string): Promise<{ address: string; mnemonic: string; warning?: string }> {
  let wallet = await Wallet.findOne({ email });
  let mnemonic: string;
  let encryptedData: { encrypted: string; iv: string; salt: string };
  let address: string;
  let warnings: string[] = [];

  if (wallet) {
    console.log('Wallet found, reusing stored mnemonic for:', email);
    mnemonic = this.decryptMnemonic(wallet.xion.encryptedMnemonic, wallet.xion.iv, wallet.xion.salt);
    encryptedData = { encrypted: wallet.xion.encryptedMnemonic, iv: wallet.xion.iv, salt: wallet.xion.salt };
    address = wallet.xion.address;
  } else {
    mnemonic = this.generateDeterministicMnemonic(email);
    const keypair = await SignArbSecp256k1HdWallet.fromMnemonic(mnemonic, { prefix: "xion", hdPaths: [makeCosmoshubPath(0)] });
    encryptedData = this.encryptMnemonic(mnemonic);
    const [{ address: newAddress }] = await keypair.getAccounts();
    address = newAddress;

    // Attempt fee grant
    try {
      await this.grantFeeAllowance(address);
    } catch (error) {
      console.error(`Fee grant failed for ${address}:`, error);
      warnings.push("Fee grant failed. You may need to fund your account manually to execute transactions.");
    }

    // Dispense test tokens
    try {
      await this.dispenseTestTokens(address, "1000000"); // 1 XION (adjust amount as needed)
    } catch (error) {
      console.error(`Test token dispensing failed for ${address}:`, error);
      warnings.push("Failed to dispense test tokens. Please use a faucet or fund your account manually.");
    }
  }

  const hashedPassword = await bcrypt.hash(this.normalizePassword(password), 12);
  if (!wallet) {
    wallet = await Wallet.create({
      email,
      password: hashedPassword,
      xion: { address, encryptedMnemonic: encryptedData.encrypted, iv: encryptedData.iv, salt: encryptedData.salt }
    });
  } else {
    wallet.password = hashedPassword;
    await wallet.save();
  }

  const keypair = await SignArbSecp256k1HdWallet.fromMnemonic(mnemonic, { prefix: "xion", hdPaths: [makeCosmoshubPath(0)] });
  this.abstractAccount = keypair;
  this.triggerAuthStateChange(true);

  console.log('Signup Data:', { email, address, mnemonic, warnings });
  return {
    address,
    mnemonic,
    warning: warnings.length > 0 ? warnings.join(" ") : undefined,
  };
}

  /**
   * Logs in a user with their email and password, verifying the account and setting up the keypair.
   * @param email User's email address.
   * @param password User's password.
   * @returns The user's keypair if login succeeds.
   * @throws {Error} If wallet not found or password is invalid.
   */
  async login(email: string, password: string): Promise<SignArbSecp256k1HdWallet> {
    const wallet = await Wallet.findOne({ email });
    if (!wallet) throw new Error("Wallet not found");

    const isPasswordValid = await bcrypt.compare(this.normalizePassword(password), wallet.password);
    if (!isPasswordValid) throw new Error("Invalid password");

    console.log('Login Wallet Data:', {
      email,
      password: this.normalizePassword(password),
      storedEncryptedMnemonic: wallet.xion.encryptedMnemonic,
      storedIV: wallet.xion.iv,
      storedSalt: wallet.xion.salt
    });

    try {
      const mnemonic = this.decryptMnemonic(
        wallet.xion.encryptedMnemonic,
        wallet.xion.iv,
        wallet.xion.salt
      );
      const keypair = await SignArbSecp256k1HdWallet.fromMnemonic(mnemonic, {
        prefix: "xion",
        hdPaths: [makeCosmoshubPath(0)],
      });

      const granter = this.getGranter();
      if (granter) {
        const accounts = await keypair.getAccounts();
        const keypairAddress = accounts[0].address;
        const pollSuccess = await this.pollForGrants(keypairAddress, granter);
        console.log('Grant Check Result:', pollSuccess);
        if (!pollSuccess) {
          console.warn('No valid grants found; proceeding without grant verification:', { grantee: keypairAddress, granter });
        }
        this.setGranter(granter);
      } else {
        console.log('No granter address provided; skipping grant check.');
      }

      this.abstractAccount = keypair;
      this.triggerAuthStateChange(true);
      return keypair;
    } catch (error) {
      console.error('Login Error:', error);
      throw new Error("Failed to login - check data integrity or grant configuration");
    }
  }

  /**
   * Requests a password recovery token for a user.
   * @param email User's email address.
   * @returns Recovery token string.
   * @throws {Error} If wallet not found.
   */
  async requestRecovery(email: string): Promise<string> {
    const wallet = await Wallet.findOne({ email });
    if (!wallet) throw new Error("Wallet not found");

    const recoveryToken = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours expiry
    wallet.recoveryToken = recoveryToken;
    wallet.recoveryTokenExpiry = expiry;
    await wallet.save();

    console.log('Recovery Token Generated:', { email, token: recoveryToken });
    return recoveryToken;
  }

  /**
   * Resets a user's password using a recovery token.
   * @param email User's email address.
   * @param token Recovery token.
   * @param newPassword New password.
   * @returns Boolean indicating success.
   * @throws {Error} If token is invalid or expired.
   */
  async resetPassword(email: string, token: string, newPassword: string): Promise<boolean> {
    const wallet = await Wallet.findOne({ email, recoveryToken: token });
    if (!wallet || (wallet.recoveryTokenExpiry && wallet.recoveryTokenExpiry < new Date())) {
      throw new Error("Invalid or expired recovery token");
    }

    const hashedPassword = await bcrypt.hash(this.normalizePassword(newPassword), 12);
    wallet.password = hashedPassword;
    await wallet.save();

    console.log('Password Reset Successful:', { email, newPassword: this.normalizePassword(newPassword) });
    return true;
  }

  /**
   * Resets a user's email address.
   * @param currentEmail Current email address.
   * @param newEmail New email address.
   * @param password User's password for verification.
   * @returns Object with success message and updated details.
   * @throws {Error} If wallet not found, password invalid, or new email already registered.
   */
  async resetEmail(currentEmail: string, newEmail: string, password: string): Promise<{ message: string; newEmail: string; address: string }> {
    const wallet = await Wallet.findOne({ email: currentEmail });
    if (!wallet) throw new Error("Wallet not found");

    const isPasswordValid = await bcrypt.compare(this.normalizePassword(password), wallet.password);
    if (!isPasswordValid) throw new Error("Invalid password");

    const existingWallet = await Wallet.findOne({ email: newEmail });
    if (existingWallet) throw new Error("New email is already registered to another wallet");

    wallet.email = newEmail;
    await wallet.save();

    console.log('Email Reset Successful:', { oldEmail: currentEmail, newEmail });
    return { message: "Email updated successfully", newEmail, address: wallet.xion.address };
  }

  /**
   * Retrieves the keypair address of the currently logged-in user.
   * @returns The Xion address of the first account, or an empty string if not logged in.
   */
  async getKeypairAddress(): Promise<string> {
    if (!this.abstractAccount) return "";
    const accounts = await this.abstractAccount.getAccounts();
    return accounts[0]?.address || "";
  }

  /**
   * Gets a signer client for executing transactions on the Xion network.
   * @returns A GranteeSignerClient instance configured with the user's keypair and granter.
   * @throws {Error} If RPC URL or abstract account is not configured.
   */
  async getSigner(): Promise<GranteeSignerClient> {
    if (!this.rpcUrl) throw new Error("Configuration not initialized");
    if (!this.abstractAccount) throw new Error("No abstract account found");
    const accounts = await this.abstractAccount.getAccounts();
    const granteeAddress = accounts[0].address;
    const granterAddress = this.getGranter();

    console.log('Granter:', granterAddress, 'Grantee:', granteeAddress);

    return await GranteeSignerClient.connectWithSigner(this.rpcUrl, this.abstractAccount, {
      gasPrice: GasPrice.fromString("0uxion"),
      granterAddress: granterAddress || undefined, // Explicitly pass undefined if no granter
      granteeAddress,
      treasuryAddress: this.treasury,
    });
  }

  /**
 * Fetches all NFTs owned by a given wallet address from a specified CW721 contract.
 * @param walletAddress The Xion address to check for NFTs.
 * @param contractAddress The CW721 contract address holding the NFTs.
 * @returns Array of NFT token IDs owned by the wallet address.
 * @throws {Error} If RPC URL is not configured or query fails.
 */
async getNFTsForAddress(walletAddress: string, contractAddress: string): Promise<string[]> {
  if (!this.rpcUrl) throw new Error("RPC URL must be configured");

  try {
    const client = await CosmWasmClient.connect(this.rpcUrl);
    // Query the CW721 contract for tokens owned by the address
    const queryMsg = {
      tokens: {
        owner: walletAddress,
        limit: 10, // Adjust limit as needed; pagination may be required for large collections
      },
    };
    const response = await client.queryContractSmart(contractAddress, queryMsg);
    
    // Response should contain a `tokens` array of token IDs
    if (!response || !Array.isArray(response.tokens)) {
      console.warn(`No NFTs found or invalid response for ${walletAddress} at ${contractAddress}`);
      return [];
    }

    console.log(`NFTs retrieved for ${walletAddress}:`, response.tokens);
    return response.tokens;
  } catch (error) {
    console.error(`Error fetching NFTs for ${walletAddress} from ${contractAddress}:`, error);
    throw new Error("Failed to fetch NFTs - ensure the contract address is valid and the network is accessible");
  }
}

/**
 * Fetches NFTs for the currently logged-in user's wallet address.
 * @param contractAddress The CW721 contract address to query.
 * @returns Array of NFT token IDs owned by the logged-in user.
 * @throws {Error} If user is not logged in or RPC URL is not configured.
 */
async getLoggedInUserNFTs(contractAddress: string): Promise<string[]> {
  if (!this.isLoggedIn || !this.abstractAccount) {
    throw new Error("User must be logged in to fetch their NFTs");
  }
  
  const walletAddress = await this.getKeypairAddress();
  return this.getNFTsForAddress(walletAddress, contractAddress);
}

  /**
   * Executes a smart contract on the Xion network.
   * @param contractAddress The Xion address of the smart contract.
   * @param msg The message to send to the contract.
   * @param memo Optional memo for the transaction.
   * @returns Object with transaction details and success information.
   * @throws {Error} If user is not logged in, RPC URL is not configured, or transaction fails.
   */
  async executeSmartContract(contractAddress: string, msg: Record<string, any>, memo?: string) {
    if (!this.isLoggedIn || !this.abstractAccount) throw new Error("User must be logged in to execute a smart contract");
    if (!this.rpcUrl) throw new Error("RPC URL must be configured");

    const signer = await this.getSigner();
    const accounts = await this.abstractAccount.getAccounts();
    const senderAddress = accounts[0].address;

    try {
      const fee = {
        amount: coins(5000, "uxion"),
        gas: "200000",
      };

      const result = await signer.execute(
        senderAddress,
        contractAddress,
        msg,
        fee,
        memo || "Smart contract execution via Looop Music Wallet"
      );

      console.log('Smart Contract Execution Result:', {
        transactionHash: result.transactionHash,
        sender: senderAddress,
        contractAddress,
        msg,
      });

      return {
        transactionHash: result.transactionHash,
        sender: senderAddress,
        contractAddress,
        msg,
      };
    } catch (error: any) {
      console.error('Error executing smart contract:', error);
      if (error.message.includes("account") && error.message.includes("not found")) {
        throw new Error("Sender account not found on Xion - fund the account with uxion tokens first");
      }
      if (error.message.includes("decoding bech32 failed")) {
        console.warn('Invalid granter address detected; execution attempted with sender as granter');
        // No retry needed since getSigner already uses sender as fallback
      }
      throw error; // Let the actual network error propagate
    }
  }

  /**
   * Logs out the current user, resetting the abstract account and auth state.
   */
  logout(): void {
    this.abstractAccount = undefined;
    this.triggerAuthStateChange(false);
  }

  /**
   * Polls the Xion network for existing fee grants between a grantee and granter.
   * @param grantee The grantee Xion address.
   * @param granter The granter Xion address.
   * @returns Boolean indicating if a valid grant exists.
   * @throws {Error} If RPC URL is not configured.
   */
  async pollForGrants(grantee: string, granter: string): Promise<boolean> {
    if (!this.rpcUrl) throw new Error("AbstraxionAuth needs to be configured.");
    const restUrl = this.restUrl || (await fetchConfig(this.rpcUrl)).restUrl;
    const url = `${restUrl}/cosmos/authz/v1beta1/grants?grantee=${grantee}&granter=${granter}`;
    console.log('Polling Grants API:', url);

    try {
      const res = await fetch(url, { cache: "no-store" });
      if (!res.ok) {
        console.error('Grant API request failed:', { status: res.status, statusText: res.statusText });
        return false;
      }
      const data = await res.json() as GrantsResponse;

      if (!data || !Array.isArray(data.grants)) {
        console.warn('Invalid grant response format:', data);
        return false;
      }
      if (data.grants.length === 0) return false;

      const currentTime = new Date().toISOString();
      return data.grants.some((grant: Grant) => !grant.expiration || grant.expiration > currentTime);
    } catch (error) {
      console.error('Error polling grants:', error);
      return false;
    }
  }

  /**
   * Grants a fee allowance to a grantee address using the granter's mnemonic.
   * @param granteeAddress The Xion address to receive the fee grant.
   * @throws {Error} If GRANTER_MNEMONIC is not set or RPC is not configured.
   */
  private async grantFeeAllowance(granteeAddress: string): Promise<void> {
    const granterMnemonic = process.env.GRANTER_MNEMONIC;
    if (!granterMnemonic) {
      console.error("GRANTER_MNEMONIC not set in .env; skipping fee grant");
      return;
    }

    if (!this.rpcUrl) throw new Error("RPC URL must be configured");

    try {
      const granterWallet = await SignArbSecp256k1HdWallet.fromMnemonic(granterMnemonic, { prefix: "xion" });
      const registry = new Registry();
      registry.register("/cosmos.feegrant.v1beta1.MsgGrantAllowance", MsgGrantAllowance);
      registry.register("/cosmos.feegrant.v1beta1.BasicAllowance", BasicAllowance);

      const client = await SigningStargateClient.connectWithSigner(this.rpcUrl, granterWallet, { registry });
      const [granterAccount] = await granterWallet.getAccounts();
      const granterAddress = granterAccount.address;

      const allowance = {
        typeUrl: "/cosmos.feegrant.v1beta1.BasicAllowance",
        value: BasicAllowance.fromPartial({ spendLimit: coins(1000000, "uxion") }),
      };

      const packedAllowance = Any.fromPartial({
        typeUrl: allowance.typeUrl,
        value: BasicAllowance.encode(allowance.value).finish(),
      });

      const msg = {
        typeUrl: "/cosmos.feegrant.v1beta1.MsgGrantAllowance",
        value: MsgGrantAllowance.fromPartial({ granter: granterAddress, grantee: granteeAddress, allowance: packedAllowance }),
      };

      const fee = { amount: coins(5000, "uxion"), gas: "200000" };
      const result = await client.signAndBroadcast(granterAddress, [msg], fee, "Granting fee allowance to new user");
      console.log(`Fee grant issued to ${granteeAddress}. Tx Hash: ${result.transactionHash}`);
    } catch (error) {
      console.error(`Failed to grant fee allowance to ${granteeAddress}:`, error);
    }
  }
}