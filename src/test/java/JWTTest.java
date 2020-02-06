import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class JWTTest {

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    private static final String SECRET = "mzrBO3RwQw1PBNTnjhlfvWHDodpajNTqaZ9q3lDISjg=";

    private static final String ISSUER = "authService";

    private static final String CUSTOMER_ID = "4097854";

    private static final String HEADER_TYP = "JWT";

    private static final String HEADER_ALG = "HS256";

    @Test
    public void testGenerateToken(){
        final String expectedToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MDk3ODU0IiwibmJmIjoxNTY0NzYxNjAwLCJpc3MiOiJhdXRoU2VydmljZSIsImV4cCI6MTU2NTM2NjQwMCwiaWF0IjoxNTY0NzYxNjAwfQ.uY9cUnLxNlWrCML5Zjm9vJ4988RYD18Oct0lVcYG5YA";
        final Algorithm algorithm = Algorithm.HMAC256(SECRET);
        final LocalDate issLocalDate = LocalDate.of(2019, 8, 3);
        final long TOKEN_DURATION_IN_DAYS = 7;

        String token = JWT.create()
                .withIssuer(ISSUER)
                .withSubject(CUSTOMER_ID)
                .withIssuedAt(convertToDate(issLocalDate))
                .withNotBefore(convertToDate(issLocalDate))
                .withExpiresAt(convertToDate(issLocalDate.plusDays(TOKEN_DURATION_IN_DAYS)))
                .sign(algorithm);

        assertEquals(expectedToken, token);
    }

    @Test
    public void testGenerateTokenWhenAlgorithIsNull(){
        final LocalDate issLocalDate = LocalDate.of(2019, 8, 3);
        final long TOKEN_DURATION_IN_DAYS = 7;

        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm cannot be null.");
        JWT.create()
            .withIssuer(ISSUER)
            .withSubject(CUSTOMER_ID)
            .withIssuedAt(convertToDate(issLocalDate))
            .withNotBefore(convertToDate(issLocalDate))
            .withExpiresAt(convertToDate(issLocalDate.plusDays(TOKEN_DURATION_IN_DAYS)))
            .sign(null);
    }

    @Test
    public void testVerifyAndDecodeTokenWhenValid(){
        final Algorithm algorithm = Algorithm.HMAC256(SECRET);
        final LocalDate issLocalDate = LocalDate.now();
        final long TOKEN_DURATION_IN_DAYS = 7;

        String token = JWT.create()
                .withIssuer(ISSUER)
                .withSubject(CUSTOMER_ID)
                .withIssuedAt(convertToDate(issLocalDate))
                .withNotBefore(convertToDate(issLocalDate))
                .withExpiresAt(convertToDate(issLocalDate.plusDays(TOKEN_DURATION_IN_DAYS)))
                .sign(algorithm);

        DecodedJWT jwt = null;
        boolean validJwt = false;
        try {
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(ISSUER)
                    .build();

            jwt = verifier.verify(token);
            validJwt = true;

        } catch(JWTVerificationException jve) {
            System.out.println(jve);
        }

        assertTrue(validJwt);

        assertEquals(jwt.getType(), HEADER_TYP);
        assertEquals(jwt.getAlgorithm(), HEADER_ALG);
        assertEquals(jwt.getIssuer(), ISSUER);
        assertEquals(jwt.getSubject(), CUSTOMER_ID);
        assertEquals(jwt.getIssuedAt(), convertToDate(issLocalDate));
        assertEquals(jwt.getNotBefore(), convertToDate(issLocalDate));
        assertEquals(jwt.getExpiresAt(), convertToDate(issLocalDate.plusDays(TOKEN_DURATION_IN_DAYS)));
    }

    @Test
    public void testVerifyAndDecodeTokenWhenInvalid(){
        final Algorithm algorithm = Algorithm.HMAC256(SECRET);

        // original token(exp - 2019-08-10): eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MDk3ODU0IiwibmJmIjoxNTY0NzYxNjAwLCJpc3MiOiJhdXRoU2VydmljZSIsImV4cCI6MTU2NTM2NjQwMCwiaWF0IjoxNTY0NzYxNjAwfQ.uY9cUnLxNlWrCML5Zjm9vJ4988RYD18Oct0lVcYG5YA
        // tampered token (exp - 2019-08-17): eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MDk3ODU0IiwibmJmIjoxNTY0NzYxNjAwLCJpc3MiOiJhdXRoU2VydmljZSIsImV4cCI6MTU2NTk3MTIwMCwiaWF0IjoxNTY0NzYxNjAwfQ.6ogOTeDUcNPwAerD85iYnHVaFEvc5RMtcadq1Rkr1Fo
        final String tamperedToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MDk3ODU0IiwibmJmIjoxNTY0NzYxNjAwLCJpc3MiOiJhdXRoU2VydmljZSIsImV4cCI6MTU2NTk3MTIwMCwiaWF0IjoxNTY0NzYxNjAwfQ.6ogOTeDUcNPwAerD85iYnHVaFEvc5RMtcadq1Rkr1Fo";


        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(ISSUER)
                .build();

        exception.expect(JWTVerificationException.class);
        exception.expectMessage(startsWith("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256"));
        verifier.verify(tamperedToken);
    }

    @Test
    public void testVerifyTokenWhenExpired(){
        final Algorithm algorithm = Algorithm.HMAC256(SECRET);
        final LocalDate issLocalDate = LocalDate.now();

        String token = JWT.create()
                .withIssuer(ISSUER)
                .withSubject(CUSTOMER_ID)
                .withIssuedAt(convertToDate(issLocalDate))
                .withNotBefore(convertToDate(issLocalDate))
                .withExpiresAt(convertToDate(issLocalDate.plusDays(-1))) // make this negative to make exp before iss
                .sign(algorithm);

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(ISSUER)
                .build();

        exception.expect(TokenExpiredException.class);
        exception.expectMessage(startsWith("The Token has expired"));
        verifier.verify(token);
    }

    @Test
    public void testVerifyTokenWhenNotYetUsable(){
        final Algorithm algorithm = Algorithm.HMAC256(SECRET);
        final LocalDate issLocalDate = LocalDate.now();
        final long TOKEN_DURATION_IN_DAYS = 7;

        String token = JWT.create()
                .withIssuer(ISSUER)
                .withSubject(CUSTOMER_ID)
                .withIssuedAt(convertToDate(issLocalDate))
                .withNotBefore(convertToDate(issLocalDate.plusDays(1)))  // token can only be used after 1 day from iss
                .withExpiresAt(convertToDate(issLocalDate.plusDays(TOKEN_DURATION_IN_DAYS)))
                .sign(algorithm);

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(ISSUER)
                .build();

        exception.expect(JWTVerificationException.class);
        exception.expectMessage(startsWith("The Token can't be used before"));
        verifier.verify(token);
    }

    @Test
    public void testSplitJWT() {
        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwidHlwIjoiQUNDRVNTIiwiZXhwIjoxNTgwMjAxNjEzLCJpYXQiOjE1ODAxOTgwMTN9.3vBBkCiXjpnQBYji3atWDTs9YIE8dK5Ma9NbZ3rK1VQ";
        String[] splittedJWT = jwt.split("\\.");
        assertEquals(splittedJWT.length, 3);
    }

    private Date convertToDate(LocalDate localDateToConvert) {
        return Date.from(localDateToConvert.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant());
    }
}
