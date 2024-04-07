# secure-keyx

> A simple npm package for exchanging and managing secrets between a client and a server using Elliptic Curve Diffie-Helman (ECDH) key exchange protocol.

## Installation

To install the package, use the following commands:  
`npm i secure-keyx` or `yarn add secure-keyx`

## Usage

The package provides two main classes:

- ClientSecureKeyExchange
- ServerSecureKeyExchange

### `ClientSecureKeyExchange`

This class is to be used in the browser environment which has the [WebCryptoAPI](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) available. This class provides 2 methods which are to be used to generate a client public key and a generate the shared secret.

### `getPublicKey()`

This method is used to generate the client public key which is required by the `ServerSecureKeyExchange` to generate the server public key and the shared secret on the server side.

### `generateSecret(serverPublicKey)`

This method is used to generate the shared secret using the public key which is gotten from the server using `ServerSecureKeyExchange`.

Example:

```javascript
import { ClientSecureKeyExchange } from "secure-keyx";
import axios from "axios";

const clientKeyExchange = new ClientSecureKeyExchange();
const clientPublicKey = await clientKeyExchange.getPublicKey();

console.log(clientPublicKey); // this will log the generated client public key

const response = await axios.get(
  `https://api.your-server.com?clientPublicKey=${clientPublicKey}`
);

const sharedSecret = await clientKeyExchange.generateSecret(response);

// proceed to use the shared secret to encrypt and decrypt payloads send from and to the server
```

### `ServerSecureKeyExchange`

This class generates the server public key, encrypts generated shared secrets, caches these secrets in redis. The key passed when creating an instance of the class is the encryption key which will be used to encrypt all generated shared secrets. The following methods are are interfaces to getting these done.

### `setRedisConnection(redisClient)`

This method is used to set a redis connection `secure-keyx` will use to cache the generated shared keys. This should be the first method called.

### `generateSecret(clientPublicKey, userID, ttl)`

This method is used to generate, encrypt and cache the shared secret. It does this using the clientPublicKey gotten from `ClientSecureKeyExchange`, 32 character encryption key passed in the class constructor and the redis connection provided using the `setRedisConnection()`.

Example:

```javascript
import { ServerSecureKeyExchange } from "secure-keyx";
import redis from "redis";

const client = redis.createClient(process.ENV.REDIS_URL);
client.connect();

app.post("/", async (req, res) => {
  const secureServerClient = new ServerSecureKeyExchange(
    process.env.ENCRYPTION_KEY
  );
  secureServerClient.setRedisConnection(client);
  const serverPublicKey = await secureServerClient.generateSecret(
    req.query.clientPublicKey
  );
  res.json(serverPublicKey);
});
```
