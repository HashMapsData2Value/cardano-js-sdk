import { Cardano, NotImplementedError } from '@cardano-sdk/core';
import {
  CommunicationType,
  GroupedAddress,
  KeyAgentType,
  SerializableLedgerKeyAgentData,
  SignBlobResult,
  TransportType
} from './types';
import { KeyAgentBase } from './KeyAgentBase';
import { TransportError } from './errors';
import DeviceConnection, { GetVersionResponse, utils } from '@cardano-foundation/ledgerjs-hw-app-cardano';
import TransportNodeHid from '@ledgerhq/hw-transport-node-hid-noevents';
import TransportWebHID from '@ledgerhq/hw-transport-webhid';
import type Transport from '@ledgerhq/hw-transport';

export interface LedgerKeyAgentProps {
  networkId: Cardano.NetworkId;
  accountIndex: number;
  knownAddresses: GroupedAddress[];
  extendedAccountPublicKey: Cardano.Bip32PublicKey;
  deviceConnection?: DeviceConnection;
  communicationType: CommunicationType;
}

export interface CreateWithDevice {
  networkId: Cardano.NetworkId;
  accountIndex?: number;
  communicationType: CommunicationType;
}

export interface GetXpubProps {
  deviceConnection?: DeviceConnection;
  communicationType: CommunicationType;
  accountIndex: number;
}

export interface CreateTransportProps {
  communicationType: CommunicationType;
  activeTransport?: TransportType;
  devicePath?: string;
}

export class LedgerKeyAgent extends KeyAgentBase {
  readonly #networkId: Cardano.NetworkId;
  readonly #accountIndex: number;
  readonly #knownAddresses: GroupedAddress[];
  readonly #extendedAccountPublicKey: Cardano.Bip32PublicKey;
  readonly #communicationType: CommunicationType;
  readonly deviceConnection?: DeviceConnection;

  constructor({
    networkId,
    accountIndex,
    knownAddresses,
    extendedAccountPublicKey,
    deviceConnection,
    communicationType
  }: LedgerKeyAgentProps) {
    super();
    this.#accountIndex = accountIndex;
    this.#networkId = networkId;
    this.#knownAddresses = knownAddresses;
    this.#extendedAccountPublicKey = extendedAccountPublicKey;
    this.#communicationType = communicationType;
    this.deviceConnection = deviceConnection;
  }

  get networkId(): Cardano.NetworkId {
    return this.#networkId;
  }

  get accountIndex(): number {
    return this.#accountIndex;
  }

  get __typename(): KeyAgentType {
    return KeyAgentType.Ledger;
  }

  get knownAddresses(): GroupedAddress[] {
    return this.#knownAddresses;
  }

  get serializableData(): SerializableLedgerKeyAgentData {
    return {
      __typename: KeyAgentType.Ledger,
      accountIndex: this.#accountIndex,
      communicationType: this.#communicationType,
      extendedAccountPublicKey: this.#extendedAccountPublicKey,
      knownAddresses: this.#knownAddresses,
      networkId: this.networkId
    };
  }

  static async getHidDeviceList(): Promise<string[]> {
    return await TransportNodeHid.list();
  }

  static async createTransport({
    communicationType,
    activeTransport,
    devicePath = ''
  }: CreateTransportProps): Promise<TransportType> {
    if (communicationType === CommunicationType.Node) {
      return await TransportNodeHid.open(devicePath);
    }
    return await (activeTransport && activeTransport instanceof TransportWebHID
      ? TransportWebHID.open(activeTransport.device)
      : TransportWebHID.request());
  }

  static async createDeviceConnection(activeTransport: Transport): Promise<DeviceConnection> {
    const deviceConnection = new DeviceConnection(activeTransport);
    // Perform app check to see if device can respond
    await deviceConnection.getVersion();
    return deviceConnection;
  }

  static async establishDeviceConnection(
    communicationType: CommunicationType,
    devicePath?: string
  ): Promise<DeviceConnection> {
    let transport;
    try {
      transport = await LedgerKeyAgent.createTransport({ communicationType, devicePath });
      if (!transport || !transport.deviceModel) {
        throw new TransportError('Transport failed');
      }
      const isSupportedLedgerModel = transport.deviceModel.id === 'nanoS' || transport.deviceModel.id === 'nanoX';
      if (!isSupportedLedgerModel) {
        throw new TransportError('Ledger device model not supported');
      }
      return await LedgerKeyAgent.createDeviceConnection(transport);
    } catch (error) {
      if (error.message.includes('cannot open device with path')) {
        throw new TransportError('Connection already established', error);
      }
      // If transport is established we need to close it so we can recover device from previous session
      if (transport) {
        // eslint-disable-next-line @typescript-eslint/no-floating-promises
        transport.close();
      }
      throw error;
    }
  }

  static async checkDeviceConnection(
    communicationType: CommunicationType,
    deviceConnection?: DeviceConnection
  ): Promise<DeviceConnection> {
    try {
      if (!deviceConnection) {
        return await LedgerKeyAgent.establishDeviceConnection(communicationType);
      }
      // Create / Check device connection with currently active transport
      return await LedgerKeyAgent.createDeviceConnection(deviceConnection.transport);
    } catch (error) {
      // Device disconnected -> re-establish connection
      if (error.name === 'DisconnectedDeviceDuringOperation') {
        return await LedgerKeyAgent.establishDeviceConnection(communicationType);
      }
      throw error;
    }
  }

  static async getXpub({
    deviceConnection,
    communicationType,
    accountIndex
  }: GetXpubProps): Promise<Cardano.Bip32PublicKey> {
    const recoveredDeviceConnection = await LedgerKeyAgent.checkDeviceConnection(communicationType, deviceConnection);
    const derivationPath = `1852'/1815'/${accountIndex}'`;
    const extendedPublicKey = await recoveredDeviceConnection.getExtendedPublicKey({
      path: utils.str_to_path(derivationPath) // BIP32Path
    });
    const xPubHex = `${extendedPublicKey.publicKeyHex}${extendedPublicKey.chainCodeHex}`;
    return Cardano.Bip32PublicKey(xPubHex);
  }

  static async getAppVersion(
    communicationType: CommunicationType,
    deviceConnection?: DeviceConnection
  ): Promise<GetVersionResponse> {
    const recoveredDeviceConnection = await LedgerKeyAgent.checkDeviceConnection(communicationType, deviceConnection);
    return await recoveredDeviceConnection.getVersion();
  }

  static async createWithDevice({ networkId, accountIndex = 0, communicationType }: CreateWithDevice) {
    const deviceListPaths = await LedgerKeyAgent.getHidDeviceList();
    const deviceConnection = await LedgerKeyAgent.establishDeviceConnection(communicationType, deviceListPaths[0]);
    const extendedAccountPublicKey = await LedgerKeyAgent.getXpub({
      accountIndex,
      communicationType,
      deviceConnection
    });

    return new LedgerKeyAgent({
      accountIndex,
      communicationType,
      deviceConnection,
      extendedAccountPublicKey,
      knownAddresses: [],
      networkId
    });
  }

  async getExtendedAccountPublicKey(): Promise<Cardano.Bip32PublicKey> {
    return this.#extendedAccountPublicKey;
  }

  async signBlob(): Promise<SignBlobResult> {
    throw new NotImplementedError('signBlob');
  }

  async derivePublicKey(): Promise<Cardano.Ed25519PublicKey> {
    throw new NotImplementedError('derivePublicKey');
  }

  async exportRootPrivateKey(): Promise<Cardano.Bip32PrivateKey> {
    throw new NotImplementedError('Operation not supported!');
  }
}
