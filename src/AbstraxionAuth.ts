// AbstraxionAuth.ts
import { GasPrice, SigningStargateClient } from "@cosmjs/stargate";
import { fetchConfig } from "@burnt-labs/constants";
import { coins, makeCosmoshubPath } from "@cosmjs/amino";
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

  getGranter(): string | undefined {
    const granter = process.env.GRANTER_ADDRESS;
    if (granter && !granter.startsWith("xion1")) {
      console.warn('GRANTER_ADDRESS is invalid; must start with "xion1". Proceeding without granter:', granter);
      return undefined;
    }
    return granter; // Returns undefined if unset or invalid
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

  private generateDeterministicMnemonic(email: string): string {
    const seed = crypto.pbkdf2Sync(email, this.serverSecret, 100000, 32, 'sha256');
    return Bip39.encode(seed).toString();
  }

  private async grantFeeAllowance(granteeAddress: string): Promise<void> {
    const granterMnemonic = process.env.GRANTER_MNEMONIC;
    if (!granterMnemonic) {
      console.error("GRANTER_MNEMONIC not set in .env; skipping fee grant");
      return;
    }

    try {
      const granterWallet = await SignArbSecp256k1HdWallet.fromMnemonic(granterMnemonic, {
        prefix: "xion",
      });

      // Create a custom registry with fee grant types
      const registry = new Registry();
      registry.register("/cosmos.feegrant.v1beta1.MsgGrantAllowance", MsgGrantAllowance);
      registry.register("/cosmos.feegrant.v1beta1.BasicAllowance", BasicAllowance);

      // Connect to Xion testnet with the custom registry
      const client = await SigningStargateClient.connectWithSigner(
        this.rpcUrl!,
        granterWallet,
        { registry } // Pass the custom registry
      );
      const [granterAccount] = await granterWallet.getAccounts();
      const granterAddress = granterAccount.address;

      // Define the fee grant allowance
      const allowance = {
        typeUrl: "/cosmos.feegrant.v1beta1.BasicAllowance",
        value: BasicAllowance.fromPartial({
          spendLimit: coins(1000000, "uxion"), // 1,000,000 uxion limit
          // expiration: null, // No expiration
        }),
      };

      const packedAllowance = Any.fromPartial({
        typeUrl: allowance.typeUrl,
        value: BasicAllowance.encode(allowance.value).finish(), // Encode directly
      });

      const msg = {
        typeUrl: "/cosmos.feegrant.v1beta1.MsgGrantAllowance",
        value: MsgGrantAllowance.fromPartial({
          granter: granterAddress,
          grantee: granteeAddress,
          allowance: packedAllowance,
        }),
      };

      const fee = {
        amount: coins(5000, "uxion"),
        gas: "200000",
      };

      const result = await client.signAndBroadcast(granterAddress, [msg], fee, "Granting fee allowance to new user");
      console.log(`Fee grant issued to ${granteeAddress}. Tx Hash: ${result.transactionHash}`);
    } catch (error) {
      console.error(`Failed to grant fee allowance to ${granteeAddress}:`, error);
    }
  }

  async signup(email: string, password: string) {
    let wallet = await Wallet.findOne({ email });
    
    let mnemonic: string;
    let encryptedData: { encrypted: string; iv: string; salt: string };
    let address: string;

    if (wallet) {
      console.log('Wallet found, reusing stored mnemonic for:', email);
      mnemonic = this.decryptMnemonic(wallet.xion.encryptedMnemonic, wallet.xion.iv, wallet.xion.salt);
      encryptedData = { encrypted: wallet.xion.encryptedMnemonic, iv: wallet.xion.iv, salt: wallet.xion.salt };
      address = wallet.xion.address;
    } else {
      mnemonic = this.generateDeterministicMnemonic(email);
      const keypair = await SignArbSecp256k1HdWallet.fromMnemonic(mnemonic, {
        prefix: "xion",
        hdPaths: [makeCosmoshubPath(0)]
      });
      encryptedData = this.encryptMnemonic(mnemonic);
      const [{ address: newAddress }] = await keypair.getAccounts();
      address = newAddress;

      // Grant fee allowance to the new address
      await this.grantFeeAllowance(address);
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

    const keypair = await SignArbSecp256k1HdWallet.fromMnemonic(mnemonic, {
      prefix: "xion",
      hdPaths: [makeCosmoshubPath(0)]
    });
    this.abstractAccount = keypair;
    this.triggerAuthStateChange(true);

    console.log('Signup Data:', { email, password: this.normalizePassword(password), address, encryptedMnemonic: encryptedData.encrypted, iv: encryptedData.iv, salt: encryptedData.salt, mnemonic });
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
    await wallet.save();

    console.log('Password Reset Successful:', { email, newPassword: this.normalizePassword(newPassword) });
    return true;
  }

  async resetEmail(currentEmail: string, newEmail: string, password: string) {
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

  async getKeypairAddress() {
    if (!this.abstractAccount) return "";
    const accounts = await this.abstractAccount.getAccounts();
    return accounts[0]?.address || "";
  }

  async getSigner(): Promise<GranteeSignerClient> {
    if (!this.rpcUrl) throw new Error("Configuration not initialized");
    if (!this.abstractAccount) throw new Error("No abstract account found");
    const accounts = await this.abstractAccount.getAccounts();
    const granteeAddress = accounts[0].address;
    const granterAddress = this.getGranter(); // Don’t fallback to granteeAddress here
  
    console.log('Granter:', granterAddress, 'Grantee:', granteeAddress);
  
    return await GranteeSignerClient.connectWithSigner(this.rpcUrl, this.abstractAccount, {
      gasPrice: GasPrice.fromString("0uxion"),
      granterAddress: granterAddress || undefined, // Explicitly pass undefined if no granter
      granteeAddress,
      treasuryAddress: this.treasury,
    });
  }

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
        return false;
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
      return false;
    }
  }
}