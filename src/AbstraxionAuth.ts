// AbstraxionAuth.ts
import { GasPrice } from "@cosmjs/stargate";
import { fetchConfig } from "@burnt-labs/constants";
import { makeCosmoshubPath } from "@cosmjs/amino";
import { GranteeSignerClient } from "./GranteeSignerClient";
import { SignArbSecp256k1HdWallet } from "./SignArbSecp256k1HdWallet";
import * as crypto from "crypto";
import { User } from "./models/User";
import bcrypt from 'bcrypt';

export interface GrantsResponse {
  grants: Grant[];
  pagination: Pagination;
}

export interface Grant {
  granter: string;
  grantee: string;
  authorization: Authorization;
  expiration: string;
}

export interface Authorization {
  "@type": string;
  grants: GrantAuthorization[];
}

export interface GrantAuthorization {
  contract: string;
  limit: Limit;
  filter: Filter;
}

export interface Limit {
  "@type": string;
  remaining: string;
}

export interface Filter {
  "@type": string;
}

export interface Pagination {
  next_key: null | string;
  total: string;
}

export class AbstraxionAuth {
  private rpcUrl?: string;
  private restUrl?: string;
  private treasury?: string;
  private serverSecret: string = process.env.SERVER_SECRET || 'your-secret-here'; // Store in .env
  private client?: GranteeSignerClient;
  abstractAccount?: SignArbSecp256k1HdWallet;
  isLoggedIn = false;
  authStateChangeSubscribers: ((isLoggedIn: boolean) => void)[] = [];

  constructor() {}

  configureAbstraxionInstance(rpc: string, restUrl?: string, treasury?: string) {
    this.rpcUrl = rpc;
    this.restUrl = restUrl;
    this.treasury = treasury;
  }

  subscribeToAuthStateChange(callback: (isLoggedIn: boolean) => void) {
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

  getGranter(): string {
    return process.env.GRANTER_ADDRESS || ""; // Store in .env or fetch dynamically
  }

  private setGranter(address: string): void {
    // Optionally store in session/db if needed
  }

  private encryptMnemonic(mnemonic: string, password: string) {
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(password + this.serverSecret, salt, 100000, 32, 'sha256');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(mnemonic, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { encrypted, iv: iv.toString('hex'), salt: salt.toString('hex') };
  }

  private decryptMnemonic(encrypted: string, iv: string, salt: string, password: string) {
    const key = crypto.pbkdf2Sync(password + this.serverSecret, salt, 100000, 32, 'sha256');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  async signup(email: string, password: string) {
    const user = await User.findOne({ email });
    if (user) throw new Error("Email already registered");

    // Generate wallet and capture mnemonic explicitly
    const keypair = await SignArbSecp256k1HdWallet.generate(24, { prefix: "xion" });
    // Temporarily deserialize to get mnemonic since it's private
    const serialized = await keypair.serialize("abstraxion");
    const tempKeypair = await SignArbSecp256k1HdWallet.deserialize(serialized, "abstraxion");
    const mnemonic = await tempKeypair.serialize("abstraxion"); // Note: This is a workaround; ideally, generate mnemonic separately
    const { encrypted, iv, salt } = this.encryptMnemonic(mnemonic, password);
    const [{ address }] = await keypair.getAccounts();

    await User.create({
      email,
      wallets: { xion: { address, encryptedMnemonic: encrypted, iv, salt } }
    });

    this.abstractAccount = keypair;
    this.triggerAuthStateChange(true);
    return { address, mnemonic }; // Return mnemonic for optional export
  }

  async login(email: string, password: string) {
    const user = await User.findOne({ email });
    if (!user || !user.wallets?.xion?.encryptedMnemonic) throw new Error("User or wallet not found");

    const isPasswordValid = await bcrypt.compare(password, user.password!);
    if (!isPasswordValid) throw new Error("Invalid password");

    const mnemonic = this.decryptMnemonic(
      user.wallets.xion.encryptedMnemonic!,
      user.wallets.xion.iv!,
      user.wallets.xion.salt!,
      password
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
      if (!pollSuccess) throw new Error("Grant verification failed");
      this.setGranter(granter);
    }

    this.abstractAccount = keypair;
    this.triggerAuthStateChange(true);
    return keypair;
  }

  async requestRecovery(email: string) {
    const user = await User.findOne({ email });
    if (!user) throw new Error("User not found");

    const recoveryToken = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    user.recoveryToken = recoveryToken;
    user.recoveryTokenExpiry = expiry;
    await user.save();

    // TODO: Send email with recovery link (e.g., `http://yourapp.com/reset?token=${recoveryToken}`)
    return recoveryToken; // For testing; in prod, email this
  }

  async resetPassword(email: string, token: string, newPassword: string) {
    const user = await User.findOne({ email, recoveryToken: token });
    if (!user || (user.recoveryTokenExpiry && user.recoveryTokenExpiry < new Date())) {
      throw new Error("Invalid or expired recovery token");
    }

    if (!user.wallets?.xion) throw new Error("Wallet not found");

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    const mnemonic = this.decryptMnemonic(
      user.wallets.xion.encryptedMnemonic!,
      user.wallets.xion.iv!,
      user.wallets.xion.salt!,
      user.password! // Old password
    );
    const { encrypted, iv, salt } = this.encryptMnemonic(mnemonic, newPassword);

    user.password = hashedPassword;
    user.wallets.xion.encryptedMnemonic = encrypted;
    user.wallets.xion.iv = iv;
    user.wallets.xion.salt = salt;
    // user.recoveryToken = null;
    // user.recoveryTokenExpiry = null;
    await user.save();

    return true;
  }

  async getKeypairAddress() {
    if (!this.abstractAccount) return "";
    const accounts = await this.abstractAccount.getAccounts();
    return accounts[0]?.address || "";
  }

  async getSigner() {
    if (!this.rpcUrl) throw new Error("Configuration not initialized");
    if (!this.abstractAccount) throw new Error("No abstract account found");
    const granterAddress = this.getGranter();
    if (!granterAddress) throw new Error("No granter found");

    const accounts = await this.abstractAccount.getAccounts();
    const granteeAddress = accounts[0].address;

    return await GranteeSignerClient.connectWithSigner(this.rpcUrl, this.abstractAccount, {
      gasPrice: GasPrice.fromString("0uxion"),
      granterAddress,
      granteeAddress,
      treasuryAddress: this.treasury,
    });
  }

  logout() {
    this.abstractAccount = undefined;
    this.triggerAuthStateChange(false);
  }

  async pollForGrants(grantee: string, granter: string): Promise<boolean> {
    if (!this.rpcUrl) throw new Error("AbstraxionAuth needs to be configured.");
    const restUrl = this.restUrl || (await fetchConfig(this.rpcUrl)).restUrl;
    const url = `${restUrl}/cosmos/authz/v1beta1/grants?grantee=${grantee}&granter=${granter}`;
    
    const res = await fetch(url, { cache: "no-store" });
    const data: GrantsResponse = await res.json();
    if (data.grants.length === 0) return false;

    const currentTime = new Date().toISOString();
    return data.grants.some((grant: Grant) => !grant.expiration || grant.expiration > currentTime);
  }
}