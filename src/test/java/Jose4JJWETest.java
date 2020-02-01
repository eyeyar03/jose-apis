import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;

import static org.junit.Assert.assertEquals;

public class Jose4JJWETest {

    @Test
    public void testJWEMessageEncryptionAndDecryption() throws JoseException, NoSuchAlgorithmException, InvalidJwtException, MalformedClaimException {
        // Part 1:  Message Encryption
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        //SecretKey secretKey = generator.generateKey();
        SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode("hkS3R3p5e6I3/lyUKxz/RQE9aMu1qTjcH3whhCaUaxg="), "AES");

        Date NOW = new Date();
        long ONE_HOUR = 1000 * 60 * 60;

        JwtClaims claims = new JwtClaims();
        claims.setIssuer("https://petcircle.com.au/auth");
        claims.setSubject("123456");
        claims.setIssuedAt(NumericDate.fromMilliseconds(NOW.getTime()));
        claims.setExpirationTime(NumericDate.fromMilliseconds(NOW.getTime() + ONE_HOUR));

        JsonWebEncryption senderJwe = new JsonWebEncryption();
        senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        senderJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        senderJwe.setKey(secretKey);
        senderJwe.setHeader("typ", "at-jwe");
        senderJwe.setPayload(claims.toJson());

        String jweToken = senderJwe.getCompactSerialization();
        System.out.println(jweToken);

        // Part 2:  Message Decryption
        JsonWebEncryption receiverJwe = new JsonWebEncryption();
        receiverJwe.setCompactSerialization(jweToken);

        assertEquals("at-jwe", receiverJwe.getHeader("typ"));

        receiverJwe.setKey(secretKey);

        JwtClaims receiverClaims = JwtClaims.parse(receiverJwe.getPlaintextString());

        assertEquals("123456", receiverClaims.getSubject());
        assertEquals("https://petcircle.com.au/auth", receiverClaims.getIssuer());
    }
}
