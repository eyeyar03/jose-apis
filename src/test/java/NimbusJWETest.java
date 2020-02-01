import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;

import static org.junit.Assert.assertEquals;

public class NimbusJWETest {

    /**
     * JWE consists of BASE64URL(UTF8(JWE Protected Header)) || '.' || BASE64URL(JWE Encrypted Key) || '.' || BASE64URL(JWE Initialization Vector) || '.' || BASE64URL(JWE Ciphertext) || '.' || BASE64URL(JWE Authentication Tag)
     */
    @Test
    public void testJWEMessageEncryptionAndDecryption() throws NoSuchAlgorithmException, JOSEException, ParseException {
        // Part 1:  Message Encryption

        /*
         * 1. Determine the Key Management Mode - this will be the alg in the header
         *    We'll use DIR (Direct Encryption) - No need to wrap CEK for our case. A Key Management Mode in which the CEK value used is the secret symmetric key value shared between the parties.
         */
        JWEAlgorithm jweAlgorithm = JWEAlgorithm.DIR;

        /*
         * 2. Determine the Encryption algorithm - this will be the enc in the header
         *    We'll use A128CBC_HS256 (AES 128) - https://tools.ietf.org/html/rfc7518#section-5.2.3
         */
        EncryptionMethod encryptionMethod = EncryptionMethod.A128CBC_HS256;


        /*
         * 3. Define access token type, we can use this to distinguish access token from refresh token.
         *    at-jwe for access token and rt-jwe for refresh token
         */
        JOSEObjectType tokenType = new JOSEObjectType("at-jwe");

        /*
         * 4. Build the header
         */
        JWEHeader jweHeader = new JWEHeader.Builder(jweAlgorithm, encryptionMethod)
                .type(tokenType)
                .build();

        /*
         * 5. Build claims set (sub, iss, iat, exp)
         *    sub (Subject) - customerId
         *    iss (Issuer) - https://petcircle.com.au/auth
         *    iat (Issued At) - current date and time
         *    exp (Expiration Time ) - 1 hour after iat
         */
        Date NOW = new Date();
        long ONE_HOUR = 1000 * 60 * 60;
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("123456")
                .issuer("https://petcircle.com.au/auth")
                .issueTime(NOW)
                .expirationTime(new Date(NOW.getTime() + ONE_HOUR))
                .build();

        /*
         * 6. Build the JWE token
         */
        EncryptedJWT encryptedJWT = new EncryptedJWT(jweHeader, jwtClaimsSet);

        /*
         * Here's how this lib shines, you can generate the token without encrypting the token first. An exception will be thrown if you force to generate the token,
         * java.lang.IllegalStateException: The JWE object must be in an encrypted or decrypted state
         * (try commenting out the following code)
         */
        // System.out.println(encryptedJWT.serialize());

        /*
         *  7. Generate and build the CEK
         *     We'll use AES (Advanced Encryption Standard) as our encryption method
         */
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(encryptionMethod.cekBitLength());
        SecretKey secretKey = generator.generateKey();
        //SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode("hkS3R3p5e6I3/lyUKxz/RQE9aMu1qTjcH3whhCaUaxg="), "AES");

        // comment this one out to get the encoded secret key
        // System.out.println(Base64.getEncoder().encodeToString(secretKey.getEncoded()));

        /*
         * 8. Encrypt the jwt
         *    this will produce something like:
         *    eyJ0eXAiOiJhdC1qd2UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..xEgPtJs5yTQwRRL6cniK9A.VS000DwDLzxkbwyqjfv-1AjlWPilwLQmmhm2juXUblwuTaJOZUPxAPeLP3mDSi9HgMA1wffd5fL2ja23FJMjVGJNVoVG00yIl8zZmXNbd_xWp9l27OnY44fJIp9M5ObG.Y1EGxuc2sl7fvgYendtlCw
         *    Notice that:
         *      a. Everything is gibberish.
         *      b. The second part was not present, it's for CEK, and we don't want it to be shared with the world. This is also why used DIR.
         */
        encryptedJWT.encrypt(new DirectEncrypter(secretKey));
        String jweToken = encryptedJWT.serialize();
        System.out.println(jweToken);

        // Part 2:  Message Decryption

        /*
         * 1. Parse JWE token
         */
        EncryptedJWT parsedJwe = EncryptedJWT.parse(jweToken);

        // check header type is at-jwe
        assertEquals("at-jwe", parsedJwe.getHeader().getType().getType());

        // check if encryptedJWT.serialize() is equal with parsedJwe.serialize()
        assertEquals(encryptedJWT.serialize(), parsedJwe.serialize());

        /*
         * We have to decrpt the token first before we can read the claim. This is another security of API. Forcing to read the claims with throw the following exception
         * java.lang.NullPointerException
         * That is probably because the claims were not decrypted yet.
         */
        // parsedJwe.getJWTClaimsSet().getSubject();

        /*
         * 2. Decrypt the parsed JWE token
         *    Even the encrypted and decrypted are of different classes. This will force us to use the correct types properly, avoiding unwanted problems.
         */
        parsedJwe.decrypt(new DirectDecrypter(secretKey));

        /*
         * From this point, we can now access the claims
         * We can assert that the claims before encryption and after decryption are the same
         * We might expect that asserting for equality for dates (i.e. iat and exp) will also succeed but it will not.
         * Probably because of the serialization and deserialization that was applied to them.
         * In fact, you can call the getTime() method of both dates and you'll notice a ~500 milliseconds difference.
         * So the YYYY-MM-DD HH:MM:SS might be the same, but the milliseconds part might be different.
         * Commenting out the last 2 lines, we'll encounter assertion error that looks like this:
         * java.lang.AssertionError: expected: java.util.Date<Sat Feb 01 23:32:48 CST 2020> but was: java.util.Date<Sat Feb 01 23:32:48 CST 2020>
         */
        assertEquals(jwtClaimsSet.getSubject(), parsedJwe.getJWTClaimsSet().getSubject());
        assertEquals(jwtClaimsSet.getIssuer(), parsedJwe.getJWTClaimsSet().getIssuer());
        //assertEquals(jwtClaimsSet.getIssueTime(), parsedJwe.getJWTClaimsSet().getIssueTime());
        //assertEquals(jwtClaimsSet.getExpirationTime(), parsedJwe.getJWTClaimsSet().getExpirationTime());
    }
}
