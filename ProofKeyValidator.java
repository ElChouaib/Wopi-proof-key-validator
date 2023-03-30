

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lu.atozdigital.edms.api.dao.service.wopi.WopiService;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.concurrent.ExecutionException;

@RequiredArgsConstructor
@Service
@Slf4j
public class ProofKeyValidator {
    private static final String WOPI_PROOF_KEY = "X-WOPI-Proof";
    private static final String WOPI_OLD_PROOF_KEY = "X-WOPI-ProofOld";
    private static final String ACCESS_TOKEN_KEY = "access_token";
    private static final String WOPI_TIMESTAMP = "X-WOPI-TimeStamp";
    private static final String ACCESS_TOKEN_TTL = "access_token_ttl";
    private static final String TEST_ENVIRONMENT = "test";
    private final WopiService wopiService;
    private final AppConstants appConstants;

    /**
     * This method checks if the wopi proof key provided in an HTTP request is valid or not.
     */
    public boolean isProofKeyValid(HttpServletRequest request) throws ExecutionException {
        
        // extract request url and params
        String wopiRequestUrl = request.getRequestURL().toString();
        String accessToken = request.getParameter(ACCESS_TOKEN_KEY);
        String accessTokenTTL = request.getParameter(ACCESS_TOKEN_TTL);
        String timestamp = request.getHeader(WOPI_TIMESTAMP);

        wopiRequestUrl = wopiRequestUrl.replace("http", "https") +
                "?access_token=" + encodeString(accessToken) +
                "&access_token_ttl=" + accessTokenTTL;

        // PART1: Check if request was made within the last 20min
        if (!isTimestampValid(timestamp)) {
            return false;
        }

        // PART2: Verify the validity of proofKey

        // get expected proof keys
        byte[] expectedProofArray = getExpectedProofBytes(wopiRequestUrl, accessToken, timestamp);

        // public keys coming from discoveryXML
        var wopiDiscovery = wopiService.getDiscoveryXML();
        String strWopiDiscoveryModulus = wopiDiscovery.getProofKey().getModulus();
        String strWopiDiscoveryExponent = wopiDiscovery.getProofKey().getExponent();
        String strWopiDiscoveryOldModulus = wopiDiscovery.getProofKey().getOldModulus();
        String strWopiDiscoveryOldExponent = wopiDiscovery.getProofKey().getOldExponent();

        // proofKey and oldProofKey provided in request
        String proofKey = request.getHeader(WOPI_PROOF_KEY);
        String oldProofKey = request.getHeader(WOPI_OLD_PROOF_KEY);

        // returns true if any of this three scenarios is successful:
        // - The X-WOPI-Proof value using the current public key
        // - The X-WOPI-ProofOld value using the current public key
        // - The X-WOPI-Proof value using the old public key

        return verifyProofKey(strWopiDiscoveryModulus, strWopiDiscoveryExponent, proofKey, expectedProofArray) ||
                verifyProofKey(strWopiDiscoveryModulus, strWopiDiscoveryExponent, oldProofKey, expectedProofArray) ||
                verifyProofKey(strWopiDiscoveryOldModulus, strWopiDiscoveryOldExponent, proofKey, expectedProofArray);

    }


    /**
     * @param strWopiProofKey    - Proof key from REST header
     * @param expectedProofArray - Byte Array from Specfication -- Contains querystring, time and
     *                          accessKey combined by defined algorithm in spec
     *                           4 bytes that represent the length, in bytes, of the access_token on the request.
     *                           The access_token.
     *                           4 bytes that represent the length, in bytes, of the full URL of the WOPI request,
     *                           including any query string parameters.
     *                           The WOPI request URL in all uppercase.
     *                           All query string parameters on the request URL should be included.
     *                           4 bytes that represent the length, in bytes, of the X-WOPI-TimeStamp value.
     *                           The X-WOPI-TimeStamp value.
     */
    public static boolean verifyProofKey(String strModulus, String strExponent,
                                         String strWopiProofKey, byte[] expectedProofArray) {
        try {
            PublicKey publicKey = getPublicKey(strModulus, strExponent);

            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(expectedProofArray);

            final byte[] signedProof = DatatypeConverter.parseBase64Binary(strWopiProofKey);

            return verifier.verify(signedProof);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | SignatureException | InvalidKeyException e) {
            return false;
        }
    }


    /**
     * Gets a public RSA Key using WOPI Discovery Modulus and Exponent for PKI Signed Validation
     */
    private static RSAPublicKey getPublicKey(String modulus, String exponent )
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger mod = new BigInteger( 1, DatatypeConverter.parseBase64Binary( modulus ) );
        BigInteger exp = new BigInteger( 1, DatatypeConverter.parseBase64Binary( exponent ) );
        KeyFactory factory = KeyFactory.getInstance( "RSA" );
        KeySpec ks = new RSAPublicKeySpec( mod, exp );

        return (RSAPublicKey) factory.generatePublic( ks );
    }


    /**
     * This method generates an expected byte array for proof.
     *
     * @param url The URL to be used in generating the expected byte array
     * @param accessToken The access token to be used in generating the expected byte array
     * @param timestampStr The timestamp string to be used in generating the expected byte array
     * @return A byte array containing the expected proof bytes
     */
    private static byte[] getExpectedProofBytes(String url, final String accessToken, final String timestampStr) {
        final int LONG_SIZE_BYTES = 8;
        // Convert access token to byte array
        final byte[] accessTokenBytes = accessToken.getBytes(StandardCharsets.UTF_8);

        // Convert URL to uppercase and get its byte array
        var upperCaseUrl = url.toUpperCase(Locale.ROOT);
        final byte[] hostUrlBytes = upperCaseUrl.getBytes(StandardCharsets.UTF_8);

        // Convert timestamp string to long
        final long timestamp = Long.parseLong(timestampStr);

        // Create byte buffer with the expected size and fill it with data
        final ByteBuffer byteBuffer = ByteBuffer.allocate(
                4 + accessTokenBytes.length + 4 + hostUrlBytes.length + 4 + 8);
        byteBuffer.putInt(accessTokenBytes.length);
        byteBuffer.put(accessTokenBytes);
        byteBuffer.putInt(hostUrlBytes.length);
        byteBuffer.put(hostUrlBytes);
        byteBuffer.putInt(LONG_SIZE_BYTES);
        byteBuffer.putLong(timestamp);

        // Return the byte array containing the expected proof bytes
        return byteBuffer.array();
    }

    /**
     * Encodes a string for use in a URL path segment by replacing dots, hyphens, and underscores with their respective
     * percent-encoded values.
     */
    private static String encodeString(String str) {
        String[] specialChars = { ".", "-", "_" };
        String[] encodedChars = { "%2E", "%2D", "%5F" };

        for (int i = 0; i < specialChars.length; i++) {
            str = str.replace(specialChars[i], encodedChars[i]);
        }

        return str;
    }

    /**
     * this method check if the given timestamp is within the last 20 minutes
     */
    private static boolean isTimestampValid(String timestamp) {
        // Get the current time
        Instant now = Instant.now();

        // Create an Instant representing "year zero"
        final String YEAR_ZERO = "0001-01-01T00:00:00Z";
        Instant yearZero = Instant.parse(YEAR_ZERO);

        // Calculate the duration between "year zero" and now
        Duration duration = Duration.between(yearZero, now);

        // Extract the first 11 characters of the timestamp (assumes ISO-8601 format) to get timestamp in seconds
        final int NBR_CHARS_TO_SUBTRACT = 11;
        String unixTime = timestamp.substring(0, Math.min(timestamp.length(), NBR_CHARS_TO_SUBTRACT));

        // Check if difference between now and wopiTimeStamp is within the last 20 minutes
        final int TWENTY_MINUTES_IN_SECONDS = 1200;
        return (duration.minus(Duration.ofSeconds(Long.parseLong(unixTime))).toSeconds() <= TWENTY_MINUTES_IN_SECONDS);
    }
}

