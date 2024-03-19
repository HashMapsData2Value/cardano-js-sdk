/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-console */
// import * as CML from '@dcspark/cardano-multiplatform-lib-nodejs';
import * as Crypto from '../../src';
Crypto.

import { HexBlob } from '@cardano-sdk/util';
import {
  arc52Vectors
} from '../ARC52TestVectors';

import * as bip39 from 'bip39';

// const printer = (b: Uint8Array) => {
//   let s = '[';
//   for (const element of b) {
//     s += `${element.toString()}, `;
//   }
//   s += ']';
//   return s;
// };

const harden = (num: number): number => 0x80_00_00_00 + num;

const Uint8ArrayToHexString = (b: Uint8Array) => { return Array.from(b).reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');}

/**
 * Test the given Bip32Ed25519 concrete implementation.
 *
 * @param name The name of the implementation.
 * @param bip32Ed25519 The concrete instance.
 */
const testBip32Ed25519 = (name: string, bip32Ed25519: Crypto.Bip32Ed25519) => {
  // eslint-disable-next-line sonarjs/cognitive-complexity
  describe(name, () => {
    // it.skip('output for ARC52 test vectors', async () => {
    //   //  expect.assertions(arc52Vectors.length);
    //   // f07e8b397c93a16c06f83c8f0c1a1866477c6090926445fc0cb1201228ace6e9
    //   // eslint-disable-next-line no-console
    //   let seedBytes: Buffer;
    //   for (const vector of arc52Vectors) {
    //     seedBytes = bip39.mnemonicToSeedSync(vector.seedPhrase);
    //     // const bip32Key = await bip32Ed25519.fromBip39Entropy_nopkdf2(seedBytes);
    //     await bip32Ed25519.fromBip39Entropy_nopkdf2(seedBytes);
    //     //  expect(bip32Key).toBe(vector.rootKey);
    //   }
    // });
    it('derive private and public key key', async () => {
        for (const vector of arc52Vectors) {
            let rootKeyHex = Uint8ArrayToHexString(vector.rootKey);
            let generatedPrivateKeyHex = Crypto.Bip32PrivateKeyHex(Uint8ArrayToHexString(vector.generatedPrivateKey));
            let generatedPublicKeyHex = Crypto.Bip32PublicKeyHex(Uint8ArrayToHexString(vector.generatedPublicKey));

            
            let calculatedPrivateKeyHex = await bip32Ed25519.derivePrivateKey(Crypto.Bip32PrivateKeyHex(rootKeyHex), vector.bip44path)
            let calculatedPublicKeyhex = await bip32Ed25519.derivePublicKey(Crypto.Bip32PublicKeyHex(rootKeyHex), vector.bip44path)

            expect(generatedPrivateKeyHex).toBe(calculatedPrivateKeyHex)
            expect(generatedPublicKeyHex).toBe(calculatedPublicKeyhex)
        }
    });
  });
};

testBip32Ed25519('SodiumBip32Ed25519', new Crypto.SodiumBip32Ed25519());
