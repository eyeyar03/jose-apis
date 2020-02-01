# Trying Java API's for JWE

## Nimbus JOSE+JWT 
Wiki: https://bitbucket.org/connect2id/nimbus-jose-jwt/wiki/Home
Version used: 8.5

## jose.4.j
Wiki: https://bitbucket.org/b_c/jose4j/wiki/Home
Version used: 0.7.0

## Goals
1. Learn how to generate JWE using the 2 libraries.
2. Which is easier to use?
3. Which is more flexible and extensible?
4. Which adheres more to the standards?
4. Does it provides validations for the headers?
   - alg
   - enc
   - typ
5. Does it provides validations for the claims?
   - iss
   - iat
   - exp
   - sub

## References
- JWT - https://tools.ietf.org/html/rfc7519
- JOSE - https://tools.ietf.org/html/rfc7165
- JWA - https://tools.ietf.org/html/rfc7518
- JWK - https://tools.ietf.org/html/rfc7517
- JWS - https://tools.ietf.org/html/rfc7515
- JWE - https://tools.ietf.org/html/rfc7516

## Tools
- JWT - https://jwt.io

## Generating Random Secret Key
```java
KeyGenerator generator = KeyGenerator.getInstance("AES"); //symmetric key
generator.init(256);
SecretKey secretKey = generator.generateKey();
Base64.getEncoder().encodeToString(secretKey.getEncoded());
```
