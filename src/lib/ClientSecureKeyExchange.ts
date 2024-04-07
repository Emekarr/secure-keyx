import { arrayBufferToHex, hexToArrayBuffer } from "./utils/utils";

export class ClientSecureKeyExchange {
  private cryptoKeyPair?: CryptoKeyPair;

  /**
   * This generates the crypto key pair that will be used to generate the ecdh key
   */
  private async generateClientKeys() {
    this.cryptoKeyPair = await window.crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      true,
      ["deriveBits", "deriveKey"]
    );
  }

  /**
   * Get the generate a client public key for the key exchange
   */
  async getPublicKey() {
    await this.generateClientKeys();
    const publicKey = await window.crypto.subtle.exportKey(
      "raw",
      this.cryptoKeyPair!.publicKey
    );
    return arrayBufferToHex(publicKey);
  }

  /**
   * Initiate the secret generation using the clients public key
   * @param serverPublicKey - Public key returned from server after initating key generation on the server side
   */
  async generateSecret(serverPublicKey: string) {
    if (!this.cryptoKeyPair)
      throw new Error(
        "call getPublicKey() method before calling generateSecret()"
      );
    const serverPublicKeyBytes = hexToArrayBuffer(serverPublicKey);
    const importedServerPublicKey = await window.crypto.subtle.importKey(
      "raw",
      serverPublicKeyBytes,
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      true,
      []
    );
    const sharedSecret = await window.crypto.subtle.deriveBits(
      {
        name: "ECDH",
        public: importedServerPublicKey,
      },
      this.cryptoKeyPair.privateKey,
      256
    );
    const secret = arrayBufferToHex(sharedSecret);
    return secret;
  }
}
