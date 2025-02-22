// GranteeSignerClient.ts
import {
  DeliverTxResponse,
  SigningCosmWasmClient,
  SigningCosmWasmClientOptions,
} from "@cosmjs/cosmwasm-stargate";
import {
  AccountData,
  EncodeObject,
  OfflineSigner,
} from "@cosmjs/proto-signing";
import {
  calculateFee,
  GasPrice,
  type Account,
  type SignerData,
  type StdFee,
} from "@cosmjs/stargate";
import { TxRaw } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import { MsgExec } from "cosmjs-types/cosmos/authz/v1beta1/tx";
import {
  HttpEndpoint,
  Tendermint37Client,
  TendermintClient,
} from "@cosmjs/tendermint-rpc";
import { customAccountFromAny } from "@burnt-labs/signers";
import { fromBech32 } from "@cosmjs/encoding/build";

function isValidBech32(address: string): boolean {
  try {
    fromBech32(address);
    return true;
  } catch {
    return false;
  }
}

export interface GranteeSignerOptions {
  readonly granterAddress?: string;
  readonly granteeAddress: string;
  readonly treasuryAddress?: string;
}

export class GranteeSignerClient extends SigningCosmWasmClient {
  protected readonly granterAddress?: string;
  private readonly _granteeAddress: string;
  private readonly _signer: OfflineSigner;
  private readonly _gasPrice?: GasPrice;
  private readonly _treasury?: string;
  private readonly _defaultGasMultiplier = 1.4;

  public get granteeAddress(): string {
    return this._granteeAddress;
  }

  public async getGranteeAccountData(): Promise<AccountData | undefined> {
    return this._signer.getAccounts().then((accounts) => {
      for (const account of accounts) {
        if (account.address === this._granteeAddress) {
          return account;
        }
      }
    });
  }

  public static async connectWithSigner(
    endpoint: string | HttpEndpoint,
    signer: OfflineSigner,
    options: SigningCosmWasmClientOptions & GranteeSignerOptions,
    retryCount: number = 0,
    maxRetries: number = 3,
  ): Promise<GranteeSignerClient> {
    try {
      console.log(`Attempting to connect to RPC: ${typeof endpoint === 'string' ? endpoint : endpoint.url}, retry: ${retryCount}`);
      const tmClient = await Tendermint37Client.connect(endpoint);
      return GranteeSignerClient.createWithSigner(tmClient, signer, options);
    } catch (error: any) {
      console.error(`Failed to connect to RPC: ${error.message}`);
      if (retryCount < maxRetries) {
        console.log(`Retrying connection, attempt ${retryCount + 1} of ${maxRetries}`);
        await new Promise((resolve) => setTimeout(resolve, 2000)); // Wait 2 seconds before retry
        return GranteeSignerClient.connectWithSigner(endpoint, signer, options, retryCount + 1, maxRetries);
      }
      throw new Error(`Failed to connect to RPC after ${maxRetries} retries: ${error.message}`);
    }
  }

  

  public static async createWithSigner(
    cometClient: TendermintClient,
    signer: OfflineSigner,
    options: SigningCosmWasmClientOptions & GranteeSignerOptions,
  ): Promise<GranteeSignerClient> {
    return new GranteeSignerClient(cometClient, signer, options);
  }

  protected constructor(
    cometClient: TendermintClient | undefined,
    signer: OfflineSigner,
    {
      granterAddress,
      granteeAddress,
      gasPrice,
      treasuryAddress,
      ...options
    }: SigningCosmWasmClientOptions & GranteeSignerOptions,
  ) {
    super(cometClient, signer, { ...options, gasPrice });
    this.granterAddress = granterAddress;

    if (!granteeAddress) {
      throw new Error("granteeAddress is required");
    }
    this._granteeAddress = granteeAddress;
    this._gasPrice = gasPrice;
    this._treasury = treasuryAddress;
    this._signer = signer;
  }

  public async getAccount(searchAddress: string): Promise<Account | null> {
    const account =
      await this.forceGetQueryClient().auth.account(searchAddress);
    if (!account) {
      return null;
    }
    return customAccountFromAny(account);
  }

  public async signAndBroadcast(
    signerAddress: string,
    messages: readonly EncodeObject[],
    fee: StdFee | "auto" | number,
    memo: string = "",
    timeoutHeight?: bigint,
    retryCount: number = 0,
    maxRetries: number = 3,
  ): Promise<DeliverTxResponse> {
    let usedFee: StdFee;
    const granter = this._treasury || this.granterAddress;

    if (this.granterAddress && signerAddress === this.granterAddress) {
      signerAddress = this.granteeAddress;
      messages = [
        {
          typeUrl: "/cosmos.authz.v1beta1.MsgExec",
          value: MsgExec.fromPartial({
            grantee: this.granteeAddress,
            msgs: messages.map((msg) => this.registry.encodeAsAny(msg)),
          }),
        },
      ];
    }

    const account = await this.getAccount(signerAddress);
    let sequence = account ? account.sequence : 0;
    const accountNumber = account ? account.accountNumber : 0;

    sequence += retryCount;

    console.log(`Broadcasting tx with signer: ${signerAddress}, sequence: ${sequence}, retry: ${retryCount}`);

    if (fee == "auto" || typeof fee === "number") {
      if (!this._gasPrice) {
        throw new Error("Gas price must be set when auto gas is used");
      }
      const gasEstimation = await this.simulate(signerAddress, messages, memo);
      const multiplier = typeof fee === "number" ? fee : this._defaultGasMultiplier;
      const calculatedFee = calculateFee(Math.round(gasEstimation * multiplier), this._gasPrice);
    
      // Only include granter if explicitly provided and valid
      usedFee = this.granterAddress && isValidBech32(this.granterAddress) 
        ? { ...calculatedFee, granter: this.granterAddress }
        : calculatedFee;
    } else {
      usedFee = this.granterAddress && isValidBech32(this.granterAddress) 
        ? { ...fee, granter: this.granterAddress }
        : fee;
    }

    const txRaw = await this.sign(
      signerAddress,
      messages,
      usedFee,
      memo,
      { accountNumber, sequence, chainId: await this.getChainId() },
    );
    const txBytes = TxRaw.encode(txRaw).finish();
    console.log(`Tx bytes: ${Buffer.from(txBytes).toString('hex')}`);

    try {
      const response = await this.broadcastTx(
        txBytes,
        this.broadcastTimeoutMs,
        this.broadcastPollIntervalMs,
      );
      return response;
    } catch (error: any) {
      if (
        error.message.includes("tx already exists in cache") &&
        retryCount < maxRetries
      ) {
        console.warn(`Tx exists in cache; retrying with sequence ${sequence + 1}`);
        return this.signAndBroadcast(
          signerAddress,
          messages,
          fee,
          memo,
          timeoutHeight,
          retryCount + 1,
          maxRetries,
        );
      }
      throw error;
    }
  }

  public async sign(
    signerAddress: string,
    messages: readonly EncodeObject[],
    fee: StdFee,
    memo: string,
    explicitSignerData?: SignerData,
  ): Promise<TxRaw> {
    if (this.grantExpiration && this.grantExpiration < new Date()) {
      throw new Error("Grant expired. Please re-authenticate.");
    }

    if (this.granterAddress && signerAddress === this.granterAddress) {
      signerAddress = this.granteeAddress;
      messages = [
        {
          typeUrl: "/cosmos.authz.v1beta1.MsgExec",
          value: MsgExec.fromPartial({
            grantee: signerAddress,
            msgs: messages.map((msg) => this.registry.encodeAsAny(msg)),
          }),
        },
      ];
    }

    return super.sign(signerAddress, messages, fee, memo, explicitSignerData);
  }

  private grantExpiration?: Date;
}