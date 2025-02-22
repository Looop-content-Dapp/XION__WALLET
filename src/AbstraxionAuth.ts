// AbstraxionAuth.ts
import { GasPrice } from "@cosmjs/stargate";
import { fetchConfig } from "@burnt-labs/constants";
import { makeCosmoshubPath } from "@cosmjs/amino";
import { GranteeSignerClient } from "./GranteeSignerClient";
import { SignArbSecp256k1HdWallet } from "./SignArbSecp256k1HdWallet";
import * as crypto from "crypto";
import { Wallet } from "./models/Wallet";
import bcrypt from 'bcrypt';
import { Bip39, Random } from "@cosmjs/crypto";

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
  private serverSecret: string = process.env.SERVER_SECRET || (() => { 
    throw new Error('SERVER_SECRET is required in .env'); 
  })();
  private client?: GranteeSignerClient;
  abstractAccount?: SignArbSecp256k1HdWallet;
  isLoggedIn = false;
  authStateChangeSubscribers: ((isLoggedIn: boolean) => void)[] = [];

  constructor() {
    console.log('Initialized with Server Secret:', this.serverSecret);
  }

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
    return process.env.GRANTER_ADDRESS || "";
  }

  private setGranter(address: string): void {
    // Optionally store in session/db if needed
  }

  private normalizePassword(password: string): string {
    return password.trim();
  }

  private encryptMnemonic(mnemonic: string) {
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

  private decryptMnemonic(encrypted: string, iv: string, salt: string) {
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

  async signup(email: string, password: string) {
    const existingWallet = await Wallet.findOne({ email });
    if (existingWallet) throw new Error("Email already registered with a wallet");

    const entropy = Random.getBytes(32);
    const mnemonic = Bip39.encode(entropy).toString();
    const keypair = await SignArbSecp256k1HdWallet.fromMnemonic(mnemonic, {
      prefix: "xion",
      hdPaths: [makeCosmoshubPath(0)]
    });
    const { encrypted, iv, salt } = this.encryptMnemonic(mnemonic);
    const [{ address }] = await keypair.getAccounts();

    const hashedPassword = await bcrypt.hash(this.normalizePassword(password), 12);
    console.log('Signup Data:', { email, password: this.normalizePassword(password), address, encryptedMnemonic: encrypted, iv, salt, mnemonic });
    await Wallet.create({
      email,
      password: hashedPassword,
      xion: { address, encryptedMnemonic: encrypted, iv, salt }
    });

    this.abstractAccount = keypair;
    this.triggerAuthStateChange(true);
    return { address, mnemonic };
  }

  async login(email: string, password: string) {
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

  async requestRecovery(email: string) {
    const wallet = await Wallet.findOne({ email });
    if (!wallet) throw new Error("Wallet not found");

    const recoveryToken = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
    wallet.recoveryToken = recoveryToken;
    wallet.recoveryTokenExpiry = expiry;
    await wallet.save();

    console.log('Recovery Token Generated:', { email, token: recoveryToken });
    return recoveryToken;
  }

  async resetPassword(email: string, token: string, newPassword: string) {
    const wallet = await Wallet.findOne({ email, recoveryToken: token });
    if (!wallet || (wallet.recoveryTokenExpiry && wallet.recoveryTokenExpiry < new Date())) {
      throw new Error("Invalid or expired recovery token");
    }

    const hashedPassword = await bcrypt.hash(this.normalizePassword(newPassword), 12);
    wallet.password = hashedPassword;
    // wallet.recoveryToken = null;
    // wallet.recoveryTokenExpiry = null;
    await wallet.save();

    console.log('Password Reset Successful:', { email, newPassword: this.normalizePassword(newPassword) });
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
    console.log('Polling Grants API:', url);

    try {
      const res = await fetch(url, { cache: "no-store" });
      if (!res.ok) {
        console.error('Grant API request failed:', { status: res.status, statusText: res.statusText });
        return false; // Fallback to false if API fails
      }
      const data = await res.json();
      console.log('Grant API Response:', data);

      if (!data || !Array.isArray(data.grants)) {
        console.warn('Invalid grant response format:', data);
        return false;
      }
      if (data.grants.length === 0) return false;

      const currentTime = new Date().toISOString();
      return data.grants.some((grant: Grant) => !grant.expiration || grant.expiration > currentTime);
    } catch (error) {
      console.error('Error polling grants:', error);
      return false; // Graceful fallback
    }
  }
}