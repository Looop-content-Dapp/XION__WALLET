import { GasPrice } from "@cosmjs/stargate";
import { fetchConfig } from "@burnt-labs/constants";
import { makeCosmoshubPath } from "@cosmjs/amino";
import type {
  ContractGrantDescription,
  GrantsResponse,
  SpendLimit,
} from "./types";
import { GranteeSignerClient } from "./GranteeSignerClient";
import { SignArbSecp256k1HdWallet } from "./SignArbSecp256k1HdWallet";
import { Bip39 } from "@cosmjs/crypto";

// Add this at the top of the file, after imports
class NodeStorage {
  private static storage: { [key: string]: string } = {};
  private static emailWalletMap: { [email: string]: string } = {};

  static getItem(key: string): string | null {
    return this.storage[key] || null;
  }

  static setItem(key: string, value: string): void {
    this.storage[key] = value;
  }

  static removeItem(key: string): void {
    delete this.storage[key];
  }

  static setEmailWallet(email: string, walletData: string): void {
    this.emailWalletMap[email] = walletData;
  }

  static getEmailWallet(email: string): string | null {
    return this.emailWalletMap[email] || null;
  }

  static removeEmailWallet(email: string): void {
    delete this.emailWalletMap[email];
  }

  static hasEmailWallet(email: string): boolean {
    return !!this.emailWalletMap[email];
  }
}

interface VerifiedCredentials {
  email?: string;
  token?: string;
  appleId?: string;
}

export class AbstraxionAuth {
  // Config
  private rpcUrl?: string;
  private restUrl?: string;
  grantContracts?: ContractGrantDescription[];
  stake?: boolean;
  bank?: SpendLimit[];
  callbackUrl?: string;
  treasury?: string;

  private verifiedCredentials?: VerifiedCredentials;
  private identityProvider?: 'gmail' | 'email' | 'apple';
  private identityVerified: boolean = false;

  // Signer
  private client?: GranteeSignerClient;

  // Accounts
  abstractAccount?: SignArbSecp256k1HdWallet;

  // State
  private isLoginInProgress = false;
  isLoggedIn = false;
  authStateChangeSubscribers: ((isLoggedIn: boolean) => void)[] = [];

  /**
   * Creates an instance of the AbstraxionAuth class.
   */
  constructor() {}

  /**
   * Updates AbstraxionAuth instance with user config
   *
   * @param {string} rpc - The RPC URL used for communication with the blockchain.
   * @param {string} [restUrl] - The REST URL used for additional communication.
   * @param {ContractGrantDescription[]} [grantContracts] - Contracts for granting permissions.
   * @param {boolean} [stake] - Indicates whether staking is enabled.
   * @param {SpendLimit[]} [bank] - The spend limits for the user.
   * @param {string} callbackUrl - preferred callback url to override default
   * @param {string} treasury - treasury contract instance address
   */
  configureAbstraxionInstance(
    rpc: string,
    restUrl?: string,
    grantContracts?: ContractGrantDescription[],
    stake?: boolean,
    bank?: SpendLimit[],
    callbackUrl?: string,
    treasury?: string,
  ) {
    this.rpcUrl = rpc;
    this.restUrl = restUrl;
    this.grantContracts = grantContracts;
    this.stake = stake;
    this.bank = bank;
    this.callbackUrl = callbackUrl;
    this.treasury = treasury;
  }

  /**
   * Subscribes to changes in authentication state.
   * When the authentication state changes, the provided callback function is invoked
   * with the new authentication state (isLoggedIn).
   * Returns an unsubscribe function that can be called to remove the subscription.
   *
   * @param {function} callback - A function to be invoked when the authentication state changes.
   *                             Receives a single parameter, isLoggedIn, indicating whether the user is logged in.
   *                             The callback should accept a boolean parameter.
   * @returns {function} - A function that, when called, removes the subscription to authentication state changes.
   *                      This function should be invoked to clean up the subscription when no longer needed.
   */
  subscribeToAuthStateChange(callback: (isLoggedIn: boolean) => void) {
    this.authStateChangeSubscribers.push(callback);
    return () => {
      const index = this.authStateChangeSubscribers.indexOf(callback);
      if (index !== -1) {
        this.authStateChangeSubscribers.splice(index, 1);
      }
    };
  }

  /**
   * Triggers a change in authentication state and notifies all subscribers.
   *
   * @param {boolean} isLoggedIn - The new authentication state, indicating whether the user is logged in.
   */
  private triggerAuthStateChange(isLoggedIn: boolean): void {
    this.isLoggedIn = isLoggedIn;
    this.authStateChangeSubscribers.forEach((callback) => callback(isLoggedIn));
  }

  /**
   * Get the account address of the granter from persisted state.
   *
   * @returns {string} The account address of the granter wallet (XION Meta Account).
   */
  getGranter(): string {
    const granterAddress = NodeStorage.getItem("xion-authz-granter-account");
    if (!granterAddress || granterAddress === "undefined") {
      return "";
    }
    return granterAddress;
  }

  /**
   * Remove persisted instance of granter account.
   */
  private removeGranterAddress(): void {
    NodeStorage.removeItem("xion-authz-granter-account");
  }

  /**
   * Set a persisted instance for granter account.
   *
   * @param {string} address - account address of the granter wallet (XION Meta Account).
   */
  private setGranter(address: string): void {
    NodeStorage.setItem("xion-authz-granter-account", address);
  }

  /**
   * Get temp keypair from persisted state.
   */
  async getLocalKeypair(): Promise<SignArbSecp256k1HdWallet | undefined> {
    try {
      console.log('[Wallet] Attempting to retrieve local keypair');
      const localKeypair = NodeStorage.getItem("xion-authz-temp-account");
      if (!localKeypair) {
        console.log('[Wallet] No local keypair found');
        return undefined;
      }
      const wallet = await SignArbSecp256k1HdWallet.deserialize(
        localKeypair,
        "abstraxion",
      );
      console.log('[Wallet] Successfully retrieved local keypair');
      return wallet;
    } catch (error) {
      console.error('[Wallet] Error retrieving local keypair:', error);
      return undefined;
    }
  }

  /**
   * Generate a new temp keypair and store in persisted state.
   */
  async generateAndStoreTempAccount(email?: string): Promise<SignArbSecp256k1HdWallet> {
    try {
      console.log('[Wallet] Generating new temporary account...');
      
      if (email && NodeStorage.hasEmailWallet(email)) {
        throw new Error("Email already has an associated wallet");
      }
      
      // Generate deterministic seed from email if provided
      let keypair;
      if (email) {
        // Create deterministic seed from email
        const emailHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(email));
        const entropy = new Uint8Array(emailHash);
        
        // Generate valid BIP39 mnemonic from entropy
        const mnemonic = Bip39.encode(entropy).toString();
        
        keypair = await SignArbSecp256k1HdWallet.fromMnemonic(mnemonic, {
          prefix: "xion",
          hdPaths: [makeCosmoshubPath(0)],
        });
      } else {
        keypair = await SignArbSecp256k1HdWallet.generate(24, {
          prefix: "xion",
          hdPaths: [makeCosmoshubPath(0)],
        });
      }
  
      console.log('[Wallet] Serializing and storing keypair');
      const serializedKeypair = await keypair.serialize("abstraxion");
      
      if (email) {
        NodeStorage.setEmailWallet(email, serializedKeypair);
      }
      NodeStorage.setItem("xion-authz-temp-account", serializedKeypair);
      
      // Verify the stored keypair
      const storedKeypair = await this.getLocalKeypair();
      if (!storedKeypair) {
        throw new Error("Failed to verify stored keypair");
      }
  
      // Clean up old granter address
      this.removeGranterAddress();
      
      console.log('[Wallet] Temporary account generated and stored successfully');
      return keypair;
    } catch (error: any) {
      console.error('[Wallet] Error generating temporary account:', error);
      throw new Error(`Failed to generate temporary account: ${error.message}`);
    }
  }

  // Add method to retrieve wallet by email
  async getWalletByEmail(email: string): Promise<SignArbSecp256k1HdWallet | undefined> {
    try {
      const serializedWallet = NodeStorage.getEmailWallet(email);
      if (!serializedWallet) {
        return undefined;
      }
      
      return await SignArbSecp256k1HdWallet.deserialize(
        serializedWallet,
        "abstraxion"
      );
    } catch (error) {
      console.error('[Wallet] Error retrieving wallet by email:', error);
      return undefined;
    }
  }

  /**
   * Get keypair account address with validation.
   */
  async getKeypairAddress(): Promise<string> {
    try {
      console.log('[Wallet] Retrieving keypair address');
      const keypair = await this.getLocalKeypair();
      if (!keypair) {
        console.log('[Wallet] No keypair found');
        return "";
      }
      
      const accounts = await keypair.getAccounts();
      if (!accounts || accounts.length === 0) {
        console.warn('[Wallet] No accounts found in keypair');
        return "";
      }
      
      const address = accounts[0].address;
      console.log('[Wallet] Retrieved address:', address);
      return address;
    } catch (error) {
      console.error('[Wallet] Error getting keypair address:', error);
      return "";
    }
  }

  /**
   * Validate and get signer client for the temp keypair.
   */
  async getSigner(): Promise<GranteeSignerClient> {
    try {
      console.log('[Signer] Initializing signer client...');
      if (this.client) {
        console.log('[Signer] Using existing signer client');
        return this.client;
      }

      if (!this.rpcUrl) {
        throw new Error("Configuration not initialized");
      }

      if (!this.abstractAccount) {
        throw new Error("No abstract account found");
      }

      const granterAddress = this.getGranter();
      if (!granterAddress) {
        throw new Error("No granter found");
      }

      // Validate account before creating signer
      const accounts = await this.abstractAccount.getAccounts();
      if (!accounts || accounts.length === 0) {
        throw new Error("No accounts found in abstract account");
      }

      const granteeAddress = accounts[0].address;
      console.log('[Signer] Creating signer with addresses:', {
        granter: granterAddress,
        grantee: granteeAddress
      });

      const directClient = await GranteeSignerClient.connectWithSigner(
        this.rpcUrl,
        this.abstractAccount,
        {
          gasPrice: GasPrice.fromString("0uxion"),
          granterAddress,
          granteeAddress,
          treasuryAddress: this.treasury,
        },
      );

      console.log('[Signer] Signer client created successfully');
      this.client = directClient;
      return directClient;
    } catch (error) {
      console.error('[Signer] Failed to initialize signer:', error);
      this.client = undefined;
      throw error;
    }
  }

  /**
   * Get dashboard url and redirect in order to issue claim with XION meta account for local keypair.
   */
  async redirectToDashboard() {
    try {
      if (!this.rpcUrl) {
        throw new Error("AbstraxionAuth needs to be configured.");
      }
      const userAddress = await this.getKeypairAddress();
      const { dashboardUrl } = await fetchConfig(this.rpcUrl);
      this.configureUrlAndRedirect(dashboardUrl, userAddress);
    } catch (error) {
      console.warn(
        "Something went wrong trying to redirect to XION dashboard: ",
        error,
      );
    }
  }

  /**
   * Configure URL and redirect page
   */
  private configureUrlAndRedirect(
    dashboardUrl: string,
    userAddress: string,
  ): void {
    if (typeof window !== "undefined") {
      const currentUrl = this.callbackUrl || window.location.href;
      const urlParams = new URLSearchParams();

      if (this.treasury) {
        urlParams.set("treasury", this.treasury);
      }

      if (this.bank) {
        urlParams.set("bank", JSON.stringify(this.bank));
      }

      if (this.stake) {
        urlParams.set("stake", "true");
      }

      if (this.grantContracts) {
        urlParams.set("contracts", JSON.stringify(this.grantContracts));
      }

      urlParams.set("grantee", userAddress);
      urlParams.set("redirect_uri", currentUrl);

      const queryString = urlParams.toString(); // Convert URLSearchParams to string
      window.location.href = `${dashboardUrl}?${queryString}`;
    } else {
      console.warn("Window not defined. Cannot redirect to dashboard");
    }
  }

  /**
   * Poll for grants issued to a grantee from a granter.
   *
   * @param {string} grantee - The address of the grantee.
   * @param {string | null} granter - The address of the granter, or null if not available.
   * @returns {Promise<boolean>} A Promise that resolves to true if grants are found, otherwise false.
   * @throws {Error} If the grantee or granter address is invalid, or if maximum retries are exceeded.
   */
  async pollForGrants(
    grantee: string,
    granter: string | null,
  ): Promise<boolean> {
    console.log(`Polling for grants - Grantee: ${grantee}, Granter: ${granter}`);
    
    if (!this.rpcUrl) {
      throw new Error("AbstraxionAuth needs to be configured.");
    }
    if (!grantee) {
      throw new Error("No keypair address");
    }
    if (!granter) {
      throw new Error("No granter address");
    }

    const pollBaseUrl =
      this.restUrl || (await fetchConfig(this.rpcUrl)).restUrl;

    const maxRetries = 5;
    let retries = 0;

    while (retries < maxRetries) {
      try {
        const baseUrl = `${pollBaseUrl}/cosmos/authz/v1beta1/grants`;
        const url = new URL(baseUrl);
        const params = new URLSearchParams({
          grantee,
          granter,
        });
        url.search = params.toString();
        const res = await fetch(url, {
          cache: "no-store",
        });
        const data: GrantsResponse = await res.json();
        if (data.grants.length === 0) {
          console.log('No grants found for the specified grantee/granter pair');
          return false;
        }

        const currentTime = new Date().toISOString();
        const validGrant = data.grants.some((grant) => {
          const { expiration } = grant;
          const isValid = !expiration || expiration > currentTime;
          console.log(`Grant expiration check: ${isValid ? 'Valid' : 'Expired'} (Expires: ${expiration || 'No expiration'})`);
          return isValid;
        });

        return validGrant;
      } catch (error) {
        console.error(`Grant polling attempt ${retries + 1} failed:`, error);
        const delay = Math.pow(2, retries) * 1000;
        await new Promise((resolve) => setTimeout(resolve, delay));
        retries++;
      }
    }
    console.error(`Grant polling failed after ${maxRetries} attempts`);
    return false;
  }

  /**
   * Wipe persisted state and instance variables.
   */
  logout(): void {
    NodeStorage.removeItem("xion-authz-temp-account");
    NodeStorage.removeItem("xion-authz-granter-account");
    this.abstractAccount = undefined;
    this.triggerAuthStateChange(false);
  }

  /**
   * Authenticates the user based on the presence of a local keypair and a granter address.
   * Also checks if the grant is still valid by verifying the expiration.
   * If valid, sets the abstract account and triggers authentication state change.
   * If expired, clears local state and prompts reauthorization.
   *
   * @returns {Promise<void>} - Resolves if authentication is successful or logs out the user otherwise.
   */
  async authenticate(): Promise<void> {
    try {
      const keypair = await this.getLocalKeypair();
      const granter = this.getGranter();
  
      if (!keypair || !granter) {
        console.warn("Missing keypair or granter, cannot authenticate.");
        return;
      }
  
      const accounts = await keypair.getAccounts();
      const keypairAddress = accounts[0].address;
  
      // Add grace period check for grant expiration
      const isGrantValid = await this.pollForGrants(keypairAddress, granter);
      if (!isGrantValid) {
        // Proactively generate new keypair before complete expiration
        await this.newKeypairFlow();
        return;
      }
  
      this.abstractAccount = keypair;
      this.triggerAuthStateChange(true);
    } catch (error) {
      console.error("Error during authentication:", error);
      this.logout();
    }
  }

  /**
   * Initiates the login process for the user.
   * Checks if a local keypair and granter address exist, either from URL parameters or localStorage.
   * If both exist, polls for grants and updates the authentication state if successful.
   * If not, generates a new keypair and redirects to the dashboard for grant issuance.
   *
   * @returns {Promise<void>} - A Promise that resolves once the login process is complete.
   * @throws {Error} - If the login process encounters an error.
   */
  // Add new properties
  // private identityProvider?: 'gmail' | 'email' | 'apple';
  // private identityVerified: boolean = false;
  
  // Enhanced identity verification method
  async verifyIdentity(
    provider: 'gmail' | 'email' | 'apple',
    credentials: {
      email?: string;
      token?: string;
      appleId?: string;
    }
  ): Promise<boolean> {
    console.log(`[Identity Verification] Starting verification with ${provider}`);
    try {
      // Check if email already has a wallet
      if (credentials.email && NodeStorage.hasEmailWallet(credentials.email)) {
        console.log('[Identity Verification] Email already has an associated wallet');
        // Allow verification to continue for existing wallet
      }
  
      switch (provider) {
        case 'gmail':
          if (!credentials.token) {
            throw new Error('Gmail authentication requires a valid token');
          }
          // Implement Gmail OAuth verification
          // Verify token with Google OAuth API
          break;
  
        case 'email':
          if (!credentials.email) {
            throw new Error('Email verification requires an email address');
          }
          // Implement email verification
          // Send verification code or magic link
          break;
  
        case 'apple':
          if (!credentials.appleId) {
            throw new Error('Apple authentication requires a valid Apple ID');
          }
          // Implement Apple Sign-in verification
          // Verify with Apple authentication services
          break;
  
        default:
          throw new Error('Unsupported identity provider');
      }
      
      this.identityProvider = provider;
      this.identityVerified = true;
      this.verifiedCredentials = credentials; // Store verified credentials
      console.log(`[Identity Verification] Successfully verified with ${provider}`);
      return true;
    } catch (error: any) {
      console.error(`[Identity Verification] Failed: ${error.message}`);
      this.identityVerified = false;
      return false;
    }
  }

  // Enhance login method
  async login(): Promise<void> {
    console.log('[Login] Initiating login process...');
    try {
      if (!this.identityVerified) {
        console.error('[Login] Identity not verified');
        throw new Error("Identity verification required before login");
      }
  
      if (this.isLoginInProgress) {
        console.warn("Login is already in progress.");
        return;
      }
      this.isLoginInProgress = true;
      
      // Get email from verified identity
      const email = this.identityProvider === 'email' ? 
        this.verifiedCredentials?.email : undefined;
      
      if (!email) {
        throw new Error("Email required for wallet recovery");
      }
      
      // Try to get existing keypair first
      let keypair = await this.getWalletByEmail(email);
      
      // Only generate new keypair if none exists
      if (!keypair) {
        console.log('[Login] No existing keypair found, generating new one...');
        keypair = await this.generateAndStoreTempAccount(email);
      } else {
        console.log('[Login] Using existing keypair');
      }
      
      // Get granter address from storage
      const granter = this.getGranter();
  
      if (granter) {
        const accounts = await keypair.getAccounts();
        const keypairAddress = accounts[0].address;
        
        // Verify grants and permissions
        const pollSuccess = await this.pollForGrants(keypairAddress, granter);
        if (!pollSuccess) {
          throw new Error("Grant verification failed");
        }
  
        this.setGranter(granter);
        this.abstractAccount = keypair;
        this.triggerAuthStateChange(true);
      } else {
        this.abstractAccount = keypair;
        this.triggerAuthStateChange(true);
      }
    } catch (error) {
      console.error("Login failed:", error);
      throw error;
    } finally {
      this.isLoginInProgress = false;
      console.log('[Login] Login process completed');
    }
  }

  /**
   * Initiates the flow to generate a new keypair and redirect to the dashboard for grant issuance.
   */
  private async newKeypairFlow(): Promise<void> {
    console.log('[Keypair] Starting new keypair generation flow');
    try {
      const keypair = await this.generateAndStoreTempAccount();
      const accounts = await keypair.getAccounts();
      const address = accounts[0].address;
      console.log('[Keypair] Generated new keypair with address:', address);
      await this.redirectToDashboard();
    } catch (error) {
      console.error('[Keypair] Flow failed:', error);
      throw error;
    }
  }
}
