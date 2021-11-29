import { Ed25519KeyHash, Ed25519PublicKey, Ed25519Signature, TransactionId } from '../../../src/Cardano';

describe('Cardano/types/Transaction', () => {
  it('TransactionId() accepts a valid transaction hash hex string', () => {
    expect(() => TransactionId('3e33018e8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d')).not.toThrow();
  });

  it('Ed25519Signature() accepts a valid signature hex string', () => {
    expect(() =>
      Ed25519Signature(
        // eslint-disable-next-line max-len
        '709f937c4ce152c81f8406c03279ff5a8556a12a8657e40a578eaaa6223d2e6a2fece39733429e3ec73a6c798561b5c2d47d82224d656b1d964cfe8b5fdffe09'
      )
    ).not.toThrow();
  });

  it('Ed25519PublicKey() accepts a valid public key hex string', () => {
    expect(() => Ed25519PublicKey('6199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d39')).not.toThrow();
  });

  it('Ed25519KeyHash() accepts a key hash hex string', () => {
    expect(() => Ed25519KeyHash('6199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d39')).not.toThrow();
  });
});
