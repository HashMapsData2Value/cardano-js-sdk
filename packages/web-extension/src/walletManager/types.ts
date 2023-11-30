import { Bip32PublicKeyHex, Hash28ByteBase16 } from '@cardano-sdk/crypto';
import { Cardano } from '@cardano-sdk/core';
import { HexBlob } from '@cardano-sdk/util';

export enum WalletType {
  InMemory = 'InMemory',
  Ledger = 'Ledger',
  Trezor = 'Trezor',
  Script = 'Script'
}

/** For BIP-32 wallets: hash of extended account public key. For script wallets: script hash */
export type WalletId = Hash28ByteBase16;

/** walletId+accountIndex (only applicable for bip32 wallets) */
export type AccountId = string;

export type Bip32WalletAccount<Metadata extends {}> = {
  accountId: AccountId;
  /** account' in cip1852 */
  accountIndex: number;
  /** e.g. account name, picture */
  metadata: Metadata;
};

export type Bip32Wallet<Metadata extends {}> = {
  walletId: WalletId;
  extendedAccountPublicKey: Bip32PublicKeyHex;
  accounts: Bip32WalletAccount<Metadata>[];
};

export type HardwareWallet<Metadata extends {}> = Bip32Wallet<Metadata> & {
  type: WalletType.Ledger | WalletType.Trezor;
};

export type InMemoryWallet<Metadata extends {}> = Bip32Wallet<Metadata> & {
  type: WalletType.InMemory;
  encryptedSecrets: {
    entropy: HexBlob;
    rootPrivateKeyBytes: HexBlob;
  };
};

export type OwnSignerAccount = {
  walletId: WalletId;
  accountId: AccountId;
};

export type ScriptWallet<Metadata extends {}> = {
  type: WalletType.Script;
  walletId: WalletId;
  /** e.g. account name, picture */
  metadata: Metadata;
  script: Cardano.Script;
  ownSigners: OwnSignerAccount[];
};

export type AnyWallet<Metadata extends {}> =
  | HardwareWallet<Metadata>
  | InMemoryWallet<Metadata>
  | ScriptWallet<Metadata>;
