// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { HealthCheckResponse, Provider } from '../../../core';

/**
 * Faucet request transaction status.
 */
export enum FaucetRequestTransactionStatus {
  Pending,
  Submitted,
  InLedger,
  Expired
}

/**
 * Result for a faucet request.
 */
export class FaucetRequestResult {
  /**
   * The transaction id of the transaction generated by this request.
   */
  txId: string;

  /**
   * Current status of the transaction generated by this request in the local chain .
   */
  status: FaucetRequestTransactionStatus;

  /**
   * Absolute time at which the transaction generated by this reuqest was inserted in a block.
   */
  time: string;

  /**
   * How many blocks has passed since our transaction was added to the Cardano blockchain. The more
   * confirmations that have occured, the more secure the transaction is.
   */
  confirmations: number;
}

/**
 * The faucet provider enable clients to request arbitrary amounts of tAda from current local network
 * to fund any address. This is useful for the setup of preconditions for end-to-end tests.
 */
export interface FaucetProvider extends Provider {
  /**
   * Request tAda to be transferred to a single given address.
   *
   * @param address The address where the tAda must be deposited.
   * @param amount  The amount of tAda to be deposited at the given address address (in lovelace).
   * @param timeout The time we are willing to wait (in milliseconds) for the faucet request
   *                transaction to be confirmed.
   * @param confirmations The number of blocks that has passed since our transaction was added to the blockchain.
   */
  request(address: string, amount: number, confirmations?: number, timeout?: number): Promise<FaucetRequestResult>;

  /**
   * Request tAda to be transferred to several given addresses.
   *
   * @param addresses The addresses where the tAda must be deposited.
   * @param amounts   The amounts of tAda to be deposited at each address (in lovelace).
   * @param timeout   The time we are willing to wait (in milliseconds) for the faucet request
   *                  transaction to be confirmed.
   * @param confirmations The number of blocks that has passed since our transaction was added to the blockchain.
   */
  multiRequest(
    addresses: string[],
    amounts: number[],
    confirmations?: number,
    timeout?: number
  ): Promise<FaucetRequestResult>;

  /**
   * Initializes the faucet provider.
   */
  start(): Promise<void>;

  /**
   * Finalizes the faucet provider.
   */
  close(): Promise<void>;

  /**
   * Performs a health check on the provider.
   *
   * @returns A promise with the healthcheck reponse.
   */
  healthCheck(): Promise<HealthCheckResponse>;
}
