import { GasPrice, SigningStargateClient, calculateFee, coins, Coin } from "@cosmjs/stargate";
import { fetchConfig } from "@burnt-labs/constants";
import { makeCosmoshubPath } from "@cosmjs/amino";
import { GranteeSignerClient } from "./GranteeSignerClient";
import { SignArbSecp256k1HdWallet } from "./SignArbSecp256k1HdWallet";
import * as crypto from "crypto";
import { Wallet } from "./models/Wallet";
import { Bip39 } from "@cosmjs/crypto";
import { MsgGrantAllowance, MsgRevokeAllowance } from "cosmjs-types/cosmos/feegrant/v1beta1/tx";
import { Any } from "cosmjs-types/google/protobuf/any";
import { BasicAllowance } from "cosmjs-types/cosmos/feegrant/v1beta1/feegrant";
import { Registry } from "@cosmjs/proto-signing/build";
import { CosmWasmClient } from "@cosmjs/cosmwasm-stargate/build";

interface GrantsResponse {
  readonly grants: readonly Grant[];
  readonly pagination: Pagination;
}

interface Grant {
  readonly granter: string;
  readonly grantee: string;
  readonly authorization: Authorization;
  readonly expiration: string | null;
}

interface Authorization {
  readonly "@type": string;
  readonly grants: readonly GrantAuthorization[];
}

interface GrantAuthorization {
  readonly contract: string;
  readonly limit: Limit;
  readonly filter: Filter;
}

interface Limit {
  readonly "@type": string;
  readonly remaining: string;
}

interface Filter {
  readonly "@type": string;
}

interface Pagination {
  readonly next_key: string | null;
  readonly total: string;
}

export class AbstraxionAuth {
  private rpcUrl?: string;
  private restUrl?: string;
  private treasury?: string;
  private readonly serverSecret: string;
  private client?: GranteeSignerClient;
  private abstractAccount?: SignArbSecp256k1HdWallet;
  private isLoggedIn: boolean = false;
  private sessionToken?: string;
  private sessionTimeout?: NodeJS.Timeout;
  private readonly authStateChangeSubscribers: ((isLoggedIn: boolean) => void)[] = [];

  constructor() {
    this.serverSecret = process.env.SERVER_SECRET || (() => { throw new Error('SERVER_SECRET is required in .env'); })();
    console.log('Initialized with Server Secret:', this.serverSecret);
  }

  configureAbstraxionInstance(rpc: string, restUrl?: string, treasury?: string): void {
    this.rpcUrl = rpc;
    this.restUrl = restUrl;
    this.treasury = treasury;
  }

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
        granteeAddress: treasuryAddress,
        treasuryAddress: this.treasury,
      });

      const fee = { amount: coins(5000, "uxion"), gas: "200000" };
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

  async signup(email: string): Promise<{ address: string; mnemonic: string; warning?: string }> {
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

      try {
        await this.grantFeeAllowance(address);
      } catch (error) {
        console.error(`Fee grant failed for ${address}:`, error);
        warnings.push("Fee grant failed. You may need to fund your account manually to execute transactions.");
      }

      try {
        await this.dispenseTestTokens(address, "1000000");
      } catch (error) {
        console.error(`Test token dispensing failed for ${address}:`, error);
        warnings.push("Failed to dispense test tokens. Please use a faucet or fund your account manually.");
      }

      wallet = await Wallet.create({
        email,
        xion: { address, encryptedMnemonic: encryptedData.encrypted, iv: encryptedData.iv, salt: encryptedData.salt }
      });
    }

    const keypair = await SignArbSecp256k1HdWallet.fromMnemonic(mnemonic, { prefix: "xion", hdPaths: [makeCosmoshubPath(0)] });
    this.abstractAccount = keypair;
    this.sessionToken = crypto.randomBytes(16).toString('hex');
    this.sessionTimeout = setTimeout(() => this.logout(), 30 * 60 * 1000); // 30 minutes
    this.triggerAuthStateChange(true);

    console.log('Signup Data:', { email, address, mnemonic, warnings });
    return { address, mnemonic, warning: warnings.length > 0 ? warnings.join(" ") : undefined };
  }

  async login(email: string): Promise<SignArbSecp256k1HdWallet> {
    const wallet = await Wallet.findOne({ email });
    if (!wallet) throw new Error("Wallet not found");

    try {
      const mnemonic = this.decryptMnemonic(wallet.xion.encryptedMnemonic, wallet.xion.iv, wallet.xion.salt);
      const keypair = await SignArbSecp256k1HdWallet.fromMnemonic(mnemonic, { prefix: "xion", hdPaths: [makeCosmoshubPath(0)] });

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
      this.sessionToken = crypto.randomBytes(16).toString('hex');
      this.sessionTimeout = setTimeout(() => this.logout(), 30 * 60 * 1000); // 30 minutes
      this.triggerAuthStateChange(true);
      return keypair;
    } catch (error) {
      console.error('Login Error:', error);
      throw new Error("Failed to login - check data integrity or grant configuration");
    }
  }

  async getBalances(address: string, denoms: string[] = ['uxion', 'ibc/57097251ED81A232CE3C9D899E7C8096D6D87EF84BA203E12E424AA4C9B57A64']): Promise<Coin[]> {
    if (!this.rpcUrl) throw new Error("RPC URL must be configured");

    const client = await CosmWasmClient.connect(this.rpcUrl);
    const balances = await Promise.all(denoms.map(denom => client.getBalance(address, denom)));
    return balances.filter(b => BigInt(b.amount) > 0);
  }

  async getTransactionHistory(address: string, limit: number = 10): Promise<any[]> {
    if (!this.rpcUrl || !this.restUrl) throw new Error("RPC and REST URLs must be configured");

    const url = `${this.restUrl}/cosmos/tx/v1beta1/txs?events=transfer.recipient='${address}'&order_by=2&pagination.limit=${limit}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error("Failed to fetch transaction history");

    const data = await res.json();
    return data.tx_responses || [];
  }

  async getFeeGrants(grantee: string): Promise<any[]> {
    if (!this.rpcUrl) throw new Error("AbstraxionAuth needs to be configured.");
    const restUrl = this.restUrl || (await fetchConfig(this.rpcUrl)).restUrl;
    const url = `${restUrl}/cosmos/feegrant/v1beta1/allowances/${grantee}`;

    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) return [];
    const data = await res.json();
    return data.allowances || [];
  }

  async revokeFeeGrant(granteeAddress: string, granterAddress: string): Promise<void> {
    const signer = await this.getSigner();
    const accounts = await this.abstractAccount!.getAccounts();
    const senderAddress = accounts[0].address;

    const registry = new Registry();
    registry.register("/cosmos.feegrant.v1beta1.MsgRevokeAllowance", MsgRevokeAllowance);

    const msg = {
      typeUrl: "/cosmos.feegrant.v1beta1.MsgRevokeAllowance",
      value: MsgRevokeAllowance.fromPartial({
        granter: granterAddress,
        grantee: granteeAddress
      })
    };

    const fee = { amount: coins(5000, "uxion"), gas: "200000" };
    await signer.signAndBroadcast(senderAddress, [msg], fee, "Revoking fee grant");
  }

  async exportWallet(email: string): Promise<{ address: string; encryptedMnemonic: string; iv: string; salt: string }> {
    const wallet = await Wallet.findOne({ email });
    if (!wallet) throw new Error("Wallet not found");

    return {
      address: wallet.xion.address,
      encryptedMnemonic: wallet.xion.encryptedMnemonic,
      iv: wallet.xion.iv,
      salt: wallet.xion.salt
    };
  }

  async resetEmail(currentEmail: string, newEmail: string): Promise<{ message: string; newEmail: string; address: string }> {
    const wallet = await Wallet.findOne({ email: currentEmail });
    if (!wallet) throw new Error("Wallet not found");

    const existingWallet = await Wallet.findOne({ email: newEmail });
    if (existingWallet) throw new Error("New email is already registered to another wallet");

    wallet.email = newEmail;
    await wallet.save();

    console.log('Email Reset Successful:', { oldEmail: currentEmail, newEmail });
    return { message: "Email updated successfully", newEmail, address: wallet.xion.address };
  }

  async getKeypairAddress(): Promise<string> {
    if (!this.abstractAccount) return "";
    const accounts = await this.abstractAccount.getAccounts();
    return accounts[0]?.address || "";
  }

  async getSigner(): Promise<GranteeSignerClient> {
    if (!this.rpcUrl) throw new Error("Configuration not initialized");
    if (!this.abstractAccount) throw new Error("No abstract account found");

    const accounts = await this.abstractAccount.getAccounts();
    const granteeAddress = accounts[0].address;
    const granterAddress = this.getGranter();

    // Check if a fee grant exists for this grantee-granter pair
    let useGranter = false;
    if (granterAddress) {
      const grants = await this.getFeeGrants(granteeAddress);
      useGranter = grants.some(grant => grant.granter === granterAddress && (!grant.expiration || new Date(grant.expiration) > new Date()));
      console.log('Fee Grant Check:', { granteeAddress, granterAddress, hasGrant: useGranter });
    }

    console.log('Granter:', granterAddress, 'Grantee:', granteeAddress, 'Using Granter:', useGranter);

    return await GranteeSignerClient.connectWithSigner(this.rpcUrl, this.abstractAccount, {
      gasPrice: GasPrice.fromString("0uxion"),
      granterAddress: useGranter ? granterAddress : undefined,
      granteeAddress,
      treasuryAddress: this.treasury,
    });
  }

  async getNFTsForAddress(walletAddress: string, contractAddress: string): Promise<string[]> {
    if (!this.rpcUrl) throw new Error("RPC URL must be configured");

    try {
      const client = await CosmWasmClient.connect(this.rpcUrl);
      const queryMsg = { tokens: { owner: walletAddress, limit: 10 } };
      const response = await client.queryContractSmart(contractAddress, queryMsg);

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

  async getLoggedInUserNFTs(contractAddress: string): Promise<string[]> {
    if (!this.isLoggedIn || !this.abstractAccount) {
      throw new Error("User must be logged in to fetch their NFTs");
    }

    const walletAddress = await this.getKeypairAddress();
    return this.getNFTsForAddress(walletAddress, contractAddress);
  }

  async executeSmartContract(contractAddress: string, msg: Record<string, any>, memo?: string) {
    if (!this.isLoggedIn || !this.abstractAccount) throw new Error("User must be logged in to execute a smart contract");
    if (!this.rpcUrl) throw new Error("RPC URL must be configured");

    const signer = await this.getSigner();
    const accounts = await this.abstractAccount.getAccounts();
    const senderAddress = accounts[0].address;

    try {
      const client = await CosmWasmClient.connect(this.rpcUrl);
      const balance = await client.getBalance(senderAddress, "uxion");
      if (BigInt(balance.amount) < 5000n) {
        throw new Error("Insufficient uxion balance to cover fees");
      }

      const fee = { amount: coins(5000, "uxion"), gas: "2000000" };
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
      if (error.message.includes("fee-grant not found")) {
        throw new Error("Fee grant not found for this address; ensure sufficient uxion balance or valid fee grant");
      }
      if (error.message.includes("account") && error.message.includes("not found")) {
        throw new Error("Sender account not found on Xion - fund the account with uxion tokens first");
      }
      if (error.message.includes("decoding bech32 failed")) {
        console.warn('Invalid granter address detected; execution attempted without granter');
      }
      throw error;
    }
  }

  logout(): void {
    this.abstractAccount = undefined;
    this.sessionToken = undefined;
    if (this.sessionTimeout) clearTimeout(this.sessionTimeout);
    this.triggerAuthStateChange(false);
  }

  getSessionToken(): string | undefined {
    return this.sessionToken;
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
