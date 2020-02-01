import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.*;

import static org.junit.Assert.*;

public class NimbusJWEVerificationTests {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private static final String KEY = "hkS3R3p5e6I3/lyUKxz/RQE9aMu1qTjcH3whhCaUaxg=";

    private static final EncryptionMethod ALG = EncryptionMethod.A128CBC_HS256;

    private static final String ENC = "AES";

    private static SecretKey SECRET_KEY;

    private static JWEDecrypter JWE_DECRYPTER;

    private static final String ISSUER = "https://petcircle.com.au/auth";

    private static final Set<String> REQUIRED_CLAIMS_SET = new HashSet<>(Arrays.asList("sub", "iss", "exp"));

    private static DefaultJWTClaimsVerifier JWT_CLAIMS_VERIFIER;

    private static final String ACCESS_TOKEN_TYPE = "at-jwe";

    private static ConfigurableJOSEProcessor JOSE_PROCESSOR;

    static {
        try {
            SECRET_KEY = new SecretKeySpec(Base64.getDecoder().decode(KEY), ENC);
            JWE_DECRYPTER = new DirectDecrypter(SECRET_KEY);

            JWT_CLAIMS_VERIFIER = new DefaultJWTClaimsVerifier(new JWTClaimsSet.Builder().issuer(ISSUER).build(), REQUIRED_CLAIMS_SET);

            JWEKeySelector jweKeySelector = new JWEDecryptionKeySelector(JWEAlgorithm.DIR, ALG, new ImmutableSecret(SECRET_KEY));
            JOSE_PROCESSOR = new DefaultJOSEProcessor();
            JOSE_PROCESSOR.setJWETypeVerifier(new DefaultJOSEObjectTypeVerifier(new JOSEObjectType(ACCESS_TOKEN_TYPE)));
            JOSE_PROCESSOR.setJWEKeySelector(jweKeySelector);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testValidToken() throws ParseException, JOSEException, BadJWTException {
        // Must not throw exception when being parsed and decrypted
        EncryptedJWT parsedToken = EncryptedJWT.parse(SampleToken.VALID.toString());

        parsedToken.decrypt(JWE_DECRYPTER);

        assertEquals("at-jwe", parsedToken.getHeader().getType().getType());

        // Must not throw exception when claims set are being verified
        JWT_CLAIMS_VERIFIER.verify(parsedToken.getJWTClaimsSet());

        assertEquals("123456", parsedToken.getJWTClaimsSet().getSubject());
        assertEquals("https://petcircle.com.au/auth", parsedToken.getJWTClaimsSet().getIssuer());
    }

    @Test
    public void testUnrecognizedToken() throws ParseException, JOSEException {
        EncryptedJWT parsedToken = EncryptedJWT.parse(SampleToken.INVALID_UNRECOGNIZED.toString());

        expectedException.expect(JOSEException.class);
        parsedToken.decrypt(JWE_DECRYPTER);
    }

    @Test
    public void testMissingSubject() throws ParseException, JOSEException, BadJOSEException {
        // note that even with the missing subject, it can pass the JOSE Processor for checking the typ
        JOSE_PROCESSOR.process(SampleToken.MISSING_SUBJECT.toString(), null);

        // it can even be parsed and decrypted
        EncryptedJWT parsedToken = EncryptedJWT.parse(SampleToken.MISSING_SUBJECT.toString());
        parsedToken.decrypt(JWE_DECRYPTER);

        // subject is null
        assertNull(parsedToken.getJWTClaimsSet().getSubject());

        // we can even read the other claims like sub
        assertEquals("https://petcircle.com.au/auth", parsedToken.getJWTClaimsSet().getIssuer());

        /*
         * this is why we need the claims verifier, it will throw an exception for this case
         * com.nimbusds.jwt.proc.BadJWTException: JWT missing required claims: [sub]
         */
        expectedException.expect(BadJWTException.class);
        JWT_CLAIMS_VERIFIER.verify(parsedToken.getJWTClaimsSet());
    }

    @Test
    public void testMissingType() throws ParseException, JOSEException, BadJOSEException {
        // note that even with the MISSING type, it can still be parsed and decrypted
        EncryptedJWT parsedToken = EncryptedJWT.parse(SampleToken.INVALID_MISSING_TYP.toString());
        parsedToken.decrypt(JWE_DECRYPTER);

        assertNull(parsedToken.getHeader().getType());

        // It can even pass the jwt claims verifier and get the claims
        JWT_CLAIMS_VERIFIER.verify(parsedToken.getJWTClaimsSet());

        assertEquals("123456", parsedToken.getJWTClaimsSet().getSubject());
        assertEquals("https://petcircle.com.au/auth", parsedToken.getJWTClaimsSet().getIssuer());

        /*
         * that is why we need the JOSE Processor for checking the header. We can put this above other validations.
         * It will throw an exception like this:
         * com.nimbusds.jose.proc.BadJOSEException: Required JOSE header "typ" (type) parameter is missing
         */
        expectedException.expect(BadJOSEException.class);
        JOSE_PROCESSOR.process(SampleToken.INVALID_MISSING_TYP.toString(), null);
    }

    @Test
    public void testWrongType() throws ParseException, JOSEException, BadJOSEException {
        // note that even with the WRONG type, it can still be parsed and decrypted
        EncryptedJWT parsedToken = EncryptedJWT.parse(SampleToken.INVALID_WRONG_TYP.toString());
        parsedToken.decrypt(JWE_DECRYPTER);

        // the token's type is rt-jwe
        assertEquals("rt-jwe", parsedToken.getHeader().getType().getType());

        // It can even pass the jwt claims verifier and get the claims
        JWT_CLAIMS_VERIFIER.verify(parsedToken.getJWTClaimsSet());

        assertEquals("123456", parsedToken.getJWTClaimsSet().getSubject());
        assertEquals("https://petcircle.com.au/auth", parsedToken.getJWTClaimsSet().getIssuer());

        /*
         * that is why we need the JOSE Processor for checking the header. We can put this above other validations.
         * It will throw an exception like this:
         * com.nimbusds.jose.proc.BadJOSEException: JOSE header "typ" (type) "rt-jwe" not allowed
         */
        expectedException.expect(BadJOSEException.class);
        JOSE_PROCESSOR.process(SampleToken.INVALID_WRONG_TYP.toString(), null);
    }

    @Test
    public void testMissingIssuer() throws ParseException, JOSEException, BadJOSEException {
        // note that even with the missing issuer, it can pass the JOSE Processor for checking the typ
        JOSE_PROCESSOR.process(SampleToken.INVALID_MISSING_ISSUER.toString(), null);

        // it can even be parsed and decrypted
        EncryptedJWT parsedToken = EncryptedJWT.parse(SampleToken.INVALID_MISSING_ISSUER.toString());
        parsedToken.decrypt(JWE_DECRYPTER);

        // issuer is null
        assertNull(parsedToken.getJWTClaimsSet().getIssuer());

        // we can even read the other claims like sub
        assertEquals("123456", parsedToken.getJWTClaimsSet().getSubject());

        /*
         * this is why we need the claims verifier, it will throw an exception for this case
         * com.nimbusds.jwt.proc.BadJWTException: JWT missing required claims: [iss]
         */
        expectedException.expect(BadJWTException.class);
        JWT_CLAIMS_VERIFIER.verify(parsedToken.getJWTClaimsSet());
    }

    @Test
    public void testMismatchedIssuer() throws ParseException, JOSEException, BadJOSEException {
        // note that even with the mismatched issuer, it can pass the JOSE Processor for checking the typ
        JOSE_PROCESSOR.process(SampleToken.INVALID_MISMATCHED_ISSUER.toString(), null);

        // it can even be parsed and decrypted
        EncryptedJWT parsedToken = EncryptedJWT.parse(SampleToken.INVALID_MISMATCHED_ISSUER.toString());
        parsedToken.decrypt(JWE_DECRYPTER);

        // issuer is null
        assertNotEquals("https://petcircle.com.au/auth", parsedToken.getJWTClaimsSet().getIssuer());

        // we can even read the other claims like sub
        assertEquals("123456", parsedToken.getJWTClaimsSet().getSubject());

        /*
         * this is why we need the claims verifier, it will throw an exception for this case
         * com.nimbusds.jwt.proc.BadJWTException: JWT "iss" claim doesn't match expected value: https://petcircle.com.au/auth1
         */
        expectedException.expect(BadJWTException.class);
        JWT_CLAIMS_VERIFIER.verify(parsedToken.getJWTClaimsSet());
    }

    @Test
    public void testExpiredToken() throws ParseException, JOSEException, BadJOSEException {
        // note that even with the expired token, it can pass the JOSE Processor for checking the typ
        JOSE_PROCESSOR.process(SampleToken.EXPIRED.toString(), null);

        // it can even be parsed and decrypted
        EncryptedJWT parsedToken = EncryptedJWT.parse(SampleToken.EXPIRED.toString());
        parsedToken.decrypt(JWE_DECRYPTER);

        // the token is already expired
        assertTrue(parsedToken.getJWTClaimsSet().getExpirationTime().before(new Date()));

        // we can even read the claims
        assertEquals("https://petcircle.com.au/auth", parsedToken.getJWTClaimsSet().getIssuer());
        assertEquals("123456", parsedToken.getJWTClaimsSet().getSubject());

        /*
         * this is why we need the claims verifier, it will throw an exception for this case
         * com.nimbusds.jwt.proc.BadJWTException: Expired JWT
         */
        expectedException.expect(BadJWTException.class);
        JWT_CLAIMS_VERIFIER.verify(parsedToken.getJWTClaimsSet());
    }

    @Test
    public void generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance(ENC);
        generator.init(ALG.cekBitLength());
        SecretKey secretKey = generator.generateKey();
        System.out.println(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
    }

    enum SampleToken {
        VALID("eyJ0eXAiOiJhdC1qd2UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..wDQ2Ye_6Dl9uUOyipi3uyA.y4sNQNHUExnD9J1Sfnv79-S51s0WwQ-3XPE6kdROP-MIwoLZwM5ITUvzjFpzWUNNyO3h-URf1VPtxzNyQeOXiuy4L05lablMyxcGFHwkjxkk234R6qPsVz9nD-L-PU3X.bqYHEGnTL5a1r4GTHef_AA"),
        EXPIRED("eyJ0eXAiOiJhdC1qd2UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..teU0-cY1KlNibCGRdNNRzw.qdSLxAGgaOcxtrvQV9dcnUspQ2JuMJAjMVGiG9T4GK_ozPYLMzk5VULYSSHHaCEUW_9srj2y0S_vphQxhH1e0lNQ_AA4I7XRCenyjqBOhNhpftkikignZGc1JNdSr4nh._8fic2sSR6vRD3UbIUMaJw"),
        MISSING_SUBJECT("eyJ0eXAiOiJhdC1qd2UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..ZPsNKLZwE6AFddjiPyNsMQ.DFn-Vh8WakMq2h6DHZQy1jPWQj0nf8nxatqoPmwr9UWJnxQuAcV7O5FLGddcNC3CVLUa9W464IwuUDTn_gBPnY95zinPHuwwAKfHvtXdC70.wK6xVF1FymwJajst_EMjcw"),
        INVALID_UNRECOGNIZED("eyJ0eXAiOiJhdC1qd2UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..9qo65OpV0LeGwZbMLsIU_w.39hx_qKTOWNhV4MS9c51BkhD3roXFk6_mzIKSWdPAD8q4j9Kxjzfwg6IoQt0aTE3QIpSPEMVnFoBy7j6xR1KqIx7-pL23Ox_B1_iFrAeqgn0pS-JQXM7HmAJbUypShTc.hgHULhHns6nlIOu7a59mkw"),
        INVALID_MISSING_TYP("eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..GvAvnLy3vYZ7AkscMNyUDQ.Jj9ofjPr4KC68l_7caf1htFdCQpveC6V2NVZF2d0r-kQ6n3SA2V7bcr48lg51q-UigOntMUD41xm-TTpwOaIno3pD7Qq6W07HyvbwREuNoaQ67Q789l4GMJaVrRcnOoq.1GD_Jl2jUZrR4-bp-Fsdwg"),
        INVALID_WRONG_TYP("eyJ0eXAiOiJydC1qd2UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..v4y6ut41KPwshFeHa3nZUQ.f4Md4gn-iDye5pampgQh0TxaFsncqQCqhZHO3vei2bSSclGjUPYkR1VXgYdAOrwayPydQczVnxD472pVFXQw3lU34eslGWwEh17jR9XX7r_oBwRa1PeJ_cJS2vrWz0nX.LTnkt2cv28F-562ZHuMKVw"),
        INVALID_MISSING_ISSUER("eyJ0eXAiOiJhdC1qd2UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..b0KkiOj0w15rGgFBPv7Xlg.9Z8B76Hbf-wWOLq4w-zBCWy5rYM_-HAp-2JCQICDz78aOzrl3GhOgCesGAoPeATptOstSaq8qunEwrE8NWXwyQ.DmCwQCQ4N0U-RL-WfjgD0g"),
        INVALID_MISMATCHED_ISSUER("eyJ0eXAiOiJhdC1qd2UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..VUZFdZx3iVw1zWP_9VSJWg.FuO1F9gkIjioZo9pR3olrDmqDaLE4xvICHQcSXjmjKb-hk02ZpIa4zlhZrkHmehBn0dz3F6Mg2GYsRUv5_WGdWSacqNh4LaEWR06ddyRtSKdx0lRFf0nsdEfqqsiPqVH.1MNrunNFWes96DgCnLqBGg");

        String value;

        SampleToken(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }
}
