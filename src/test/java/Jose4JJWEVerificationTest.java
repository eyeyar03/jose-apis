import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Reference: https://bitbucket.org/b_c/jose4j/wiki/JWE%20Examples
 */
public class Jose4JJWEVerificationTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private static final String KEY = "hkS3R3p5e6I3/lyUKxz/RQE9aMu1qTjcH3whhCaUaxg=";

    private static  SecretKey SECRET_KEY;

    private static AlgorithmConstraints ALGORITHM_CONSTRAINT;

    private static AlgorithmConstraints ENCRYPTION_CONSTRAINT;

    private static JwtConsumer JWT_CONSUMER;


    static {
        SECRET_KEY = new SecretKeySpec(Base64.getDecoder().decode(KEY), "AES");

        ALGORITHM_CONSTRAINT = new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, KeyManagementAlgorithmIdentifiers.DIRECT);
        ENCRYPTION_CONSTRAINT = new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);

        JWT_CONSUMER = new JwtConsumerBuilder()
                .setDecryptionKey(SECRET_KEY)
                .setDisableRequireSignature() // probably this is only needed in JWS
                .setRequireIssuedAt()
                .setRequireExpirationTime()
                .setRequireSubject()
                .setEnableRequireEncryption()
                .setExpectedIssuer(true, "https://petcircle.com.au/auth")
                .setExpectedType(true, "at-jwe")
                .setJweAlgorithmConstraints(ALGORITHM_CONSTRAINT)
                .setJweContentEncryptionAlgorithmConstraints(ENCRYPTION_CONSTRAINT)
                .build();
    }

    @Test
    public void testValidToken() throws JoseException, InvalidJwtException, MalformedClaimException {

        /**JsonWebEncryption receiverJwe = new JsonWebEncryption();
        receiverJwe.setAlgorithmConstraints(ALGORITHM_CONSTRAINT);
        receiverJwe.setContentEncryptionAlgorithmConstraints(ENCRYPTION_CONSTRAINT);
        receiverJwe.setKey(SECRET_KEY);
        receiverJwe.setCompactSerialization(SampleToken.VALID.toString());

        JwtClaims claims = JwtClaims.parse(receiverJwe.getPlaintextString());
        assertEquals("https://petcircle.com.au/auth", claims.getIssuer());
        assertEquals("123456", claims.getSubject());*/

        JwtClaims claims = JWT_CONSUMER.processToClaims(SampleToken.VALID.toString());

        assertEquals("https://petcircle.com.au/auth", claims.getIssuer());
        assertEquals("123456", claims.getSubject());

    }

    @Test
    public void testExpiredToken() {
        try {
            JWT_CONSUMER.processToClaims(SampleToken.EXPIRED.toString());

        } catch(InvalidJwtException e) {
            // The API offers a way on telling if the token is already expired
            assertTrue(e.hasExpired());
        }
    }

    @Test
    public void testUnrecognizedToken() throws InvalidJwtException {
        expectedException.expect(InvalidJwtException.class);
        JWT_CONSUMER.processToClaims(SampleToken.INVALID_UNRECOGNIZED.toString());
    }

    @Test
    public void testMissingSubject() throws InvalidJwtException {
        expectedException.expect(InvalidJwtException.class);
        JWT_CONSUMER.processToClaims(SampleToken.MISSING_SUBJECT.toString());
    }

    @Test
    public void testMissingType() throws InvalidJwtException {
        expectedException.expect(InvalidJwtException.class);
        JWT_CONSUMER.processToClaims(SampleToken.INVALID_MISSING_TYP.toString());
    }

    @Test
    public void testWrongType() throws InvalidJwtException {
        expectedException.expect(InvalidJwtException.class);
        JWT_CONSUMER.processToClaims(SampleToken.INVALID_WRONG_TYP.toString());
    }

    @Test
    public void testMissingIssuer() throws InvalidJwtException {
        expectedException.expect(InvalidJwtException.class);
        JWT_CONSUMER.processToClaims(SampleToken.INVALID_MISSING_ISSUER.toString());
    }

    @Test
    public void testMismatchedIssuer() throws InvalidJwtException {
        expectedException.expect(InvalidJwtException.class);
        JWT_CONSUMER.processToClaims(SampleToken.INVALID_MISMATCHED_ISSUER.toString());
    }


    enum SampleToken {
        VALID("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiYXQtandlIn0..lffC5rxs-srdbKeuAIWWsQ.8HcIvFFRzd7Ucqlq7mvZV-tdVo_U4P7GDAd1gNS5tHEs-GH8heOwLTjYNKsU3_IuCvInzlUymkq4Kc7dqAPunm1ZsnzzRN3rSoPqjK5LckiaVHAP69dPW8peTOJIYrh9.iTu3A9IloC8wYENog4R33g"),
        EXPIRED("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiYXQtandlIn0..F6aUUa5jMMcaPoWRsQo-5Q.53zg0PPSq1OUwTiY5-yZZl7tP96_dnpvrXwY8G2xygV0UWolWuDEmISkiV97kSBlp_-LlgzNQ04PO7zTjeb_5005vruWr7lKWXfe0emB6tmD0osEXKk7TIt1yb66ICkL.6hokMNPPEQhC5FgahI3DgQ"),
        MISSING_SUBJECT("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiYXQtandlIn0..qFJ8t9NJsZRqdBEwY3ZxIw.zql0qGvx4i5N1xj-Pc-iLBjUoPdWsPYe3ukrF0I1qfTugzVvtFw7Kda9oIVjzCjVG9Dh8Ktj576vIIMZzaB6jlJCuAdlsIT_UmEknD-vH-8.Uqwe0Y011qTT9JPN1NJgQA"),
        INVALID_UNRECOGNIZED("eyJ0eXAiOiJhdC1qd2UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..9qo65OpV0LeGwZbMLsIU_w.39hx_qKTOWNhV4MS9c51BkhD3roXFk6_mzIKSWdPAD8q4j9Kxjzfwg6IoQt0aTE3QIpSPEMVnFoBy7j6xR1KqIx7-pL23Ox_B1_iFrAeqgn0pS-JQXM7HmAJbUypShTc.hgHULhHns6nlIOu7a59mkw"),
        INVALID_MISSING_TYP("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..mmDc392bon5nbNf0XKHFgA.6x2wACYbZRnd1uEA8i5W287phxJqCk9nnm0fE1O_HViapvgpgdvOa4psuA_GKS-UcDjxR9weXpkpe51J2S4zuTZwcbF9ZgEImuIhmFmQfFXiDaxda2cRegi320HB4Zn6.gYmmDGacxCTmICkRFY7F_g"),
        INVALID_WRONG_TYP("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoicnQtandlIn0..bKE3N0StWPDYFzj6P64Jsw.gFKSRWGuiHi0lT_AoAZcjnNkiOTRcNuEn6Oobf-xSXcAqsXYfQyYSfPUiXv-1CPakSmGlqkM5iWCWWu5u2ldSfqiP8e3ukhMp24ZQX4DtIOJ0caqudLMRmGaM2Om3uiW.L41DzsxFxEqtlyC6p3NyoA"),
        INVALID_MISSING_ISSUER("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiYXQtandlIn0..0Gu0fsEhlAnjW1nq7YzQgA.Sp1K0TP3yPnVQbaNUbQX4DoO88aY5ZLUVFtjanIaPXkP2QZwfGuthYYsadkiSdKRTiSGFDPy3lKDu7_3oBANWQ.8gv7KSGOJnM4oh9J9z7VMg"),
        INVALID_MISMATCHED_ISSUER("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiYXQtandlIn0..xFD1lFtnaDlpawCmq6jOkQ.OkYSQ4UmVG6aCVTt8eNLHUxgI8_jep7Vn2_uGdtURyhrgHbli-nPQS33Ty-T_rajolTUyTEo8uW62NTCZ1PpmFIfIXTuRoKP-HeTRNFq1Rvp430_Xc7c4f3hTe-_gjdS.q7ezfIEOE0w3IMB30kgB-w");

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
