import crypto from "crypto";
import { RedisClientType } from "redis";
import { verifyTextLength } from "./utils/validator";

export class ServerSecureKeyExchange {
  private redisClient?: RedisClientType<any>;

  /**
   * Create a new instance of the SecureKeyExchange class.
   * @param key - This is a 32 character encryption key used to encrypt the ECDH secrets stored in redis.
   */
  constructor(private key: string) {
    const is32 = verifyTextLength(this.key, 32);
    if (!is32)
      throw new Error(
        "constructor param key must consist of only 32 characters"
      );
  }

  /**
   * Set Redis connection for SecureKeyExchange to cache generated secrets.
   * @param redisClient - RedisClientType
   */
  setRedisConnection(redisClient: RedisClientType<any>) {
    this.redisClient = redisClient;
    return this;
  }

  /**
   * This is used to generated ECDH keys on the server side
   */
  private generateServerKeys() {
    const ecdh = crypto.createECDH("prime256v1");
    ecdh.generateKeys("hex");
    return ecdh;
  }

  /**
   * This is used to encrypt the generated secrets using the key passed in through the constructor
   * @param secret - The generated secret
   */
  private encryptSecret(secret: string) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.key, iv);
    const encrypted = Buffer.concat([
      cipher.update(secret, "utf8"),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();
    const encryptedSecret = Buffer.concat([iv, encrypted, authTag]);
    return encryptedSecret.toString("hex");
  }

  /**
   * This is used to cache the encrypted clients secrets using the provided redis connection
   * @param encryptSecret - The encrypted version of the generated secret
   * @param userID - Unique identifier for the user initating the key exchange
   * @param ttl - The expiry time of the cached secret. Defaults to 5 minutes
   */
  private async cacheSecret(
    encryptSecret: string,
    userID: string,
    ttl: number
  ) {
    await this.redisClient?.set(`${userID}-secure-keyx-secret`, encryptSecret);
    await this.redisClient?.expire(`${userID}-secure-keyx-secret`, ttl);
  }

  /**
   * Initiate the secret generation using the clients public key
   * @param clientPublicKey - Client Public key generated from the SecureKeyExchange client package
   * @param userID - Unique identifier for the user initating the key exchange
   * @param ttl - Set the time for the generated secrets to expire and be invalid. Defaults to 5 minutes
   */
  async generateSecret(
    clientPublicKey: string,
    userID: string,
    ttl: number = 300
  ) {
    if (!clientPublicKey || !userID)
      throw new Error(
        "userID and clientPublicKey are both required parameters"
      );
    const ecdh = this.generateServerKeys();
    const sharedSecret = ecdh.computeSecret(clientPublicKey, "hex", "hex");
    const encryptedSecret = this.encryptSecret(sharedSecret);
    await this.cacheSecret(encryptedSecret, userID, ttl);
    return ecdh.getPublicKey("hex");
  }
}
