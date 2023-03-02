package lu.atozdigital.edms.api.wopi_web._utils;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lu.atozdigital.edms.api.dao.service.wopi.WopiService;
import org.springframework.stereotype.Service;

import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Locale;
import java.util.concurrent.ExecutionException;

@RequiredArgsConstructor
@Service
@Slf4j
public class ProofKeyValidator {
    private final WopiService wopiService;
    /**
     * Tests different proof key scenarios
     *
     * @throws Exception
     */

    // example of inputs in first test case - ProofKeys.CurrentValid.OldValid
    // wopiRequestUrl: http://wopi.findl.lu/wopi/files/20fc8815-9158-49f9-87d6-de732ed344bb
    // proofKey: X4T35ul1o8gzgo+wgIDL9ANQEl3IPB4jQmTFrLjtHWd14me0h6Js4JUepx9rpF1ZVu4yxphrhUA5fwRk9EAP9Yq4V2+ROEOT9Tn9gBf1qqODN/QrCzRIGL7exzAy3zaabCY1TTJ1HYzXc/h5PZMwo4BvYhIA8ZHhSKsNBxJwOty2IiMH9uc57ewKnXtpBfmEg7aIidLEAr0LEj6lKotY+yl7pYCnWlm0cD92DSFPVz8HvtuVO4LtqcGdP0ZxbFmiMBjce283o/pU5wrfW3IspIJawSCD7y6HtIebXCvfHlUAfslnrEXD6XmtftzKXMnYSqVCGQ6NN18/KiHG5WD3tQ==
    // oldProofKey: U7z26Ca8jKFob6gdplOpRKi0dZbmjA8G0YOm7vf0cNAaiWSDYTjoaRVMkGTgumwS/iHDDyO5nO1zd+7Eyru0fM2IFJArTvZu40nlUUazc8zuUpC1vwWkoW8NZOjeQF1VsChtRE2B4sasWwyEFj1F3Gg66LZjHG5bbxFnhxRsjOfnZdf7LBvNg3s/+QMulSQ42JaSwcgn9hVsA1BJz6Labik1wv2UJegBKjGLUw4Kt7fmwfF6WmgMrEsP8PZ4oLLumx/jKMy8TpM9ZQ4UztM/8e6iP1nLXd7sFoph9SGuLldgh2UlQOAD/BKiJbImx3Ug/D/DzgYRWJ7ahvHyvhQJkQ==
    // accessToken: eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJOTzNoVVh5dGYtTVR1VTVhZVNNX0lvcWtyMVp0bVVaVEFuS2d4T25qR09jIn0.eyJleHAiOjE2Nzc3NTA3MDIsImlhdCI6MTY3Nzc0OTgwMiwianRpIjoiN2E5YTRhYTQtYjFiYi00OWU4LTk0Y2QtYTcwMGI2OTcxMjhmIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLmZpbmRsLmx1L2F1dGgvcmVhbG1zL2VkbXMtdjIiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNWRhMmQ1NjAtZmMxMS00NDdlLWEzN2UtMzYxYmIzMTU3OTRkIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYW5ndWxhci1lZG1zIiwic2Vzc2lvbl9zdGF0ZSI6Ijk3ODNiMTY2LWM1ZTctNGRlNS05YmJiLTBlNWYwYTkwMzU3OSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cHM6Ly9idWNrbGUuZmluZGwubHUvIiwiaHR0cDovL2xvY2FsaG9zdDo4MDgxIiwiaHR0cHM6Ly9lZG1zLmZpbmRsLmx1IiwiaHR0cHM6Ly9kb2NzLmF0b3otZGlnaXRhbC5sdSIsImh0dHA6Ly8xMjcuMC4wLjE6ODA4MSIsImh0dHA6Ly9sb2NhbGhvc3Q6NDIwMCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1lZG1zLXYyIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiQ2hvdWFpYiBFTE1BS0hMT1VLIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiY2hvdWFpYi5lbG1ha2hsb3VrQGF0b3otZGlnaXRhbC5sdSIsImdpdmVuX25hbWUiOiJDaG91YWliIiwiZmFtaWx5X25hbWUiOiJFTE1BS0hMT1VLIiwiZW1haWwiOiJjaG91YWliLmVsbWFraGxvdWtAYXRvei1kaWdpdGFsLmx1In0.DwRQR9nkV2VCTCCETwqwue_XA8nXQdovOKG-I_ryk9wQKRuFTpP0lNU6DJPXKNDU7HcosU3TgJOSKZKtDqJviG0CXTmM8tSzIe9QL9x9wJApeeLVRQYCFV2NRtwPuQMjuYM4-o_qGHg9X49wzjJLINwQwuoYW4vOA864AE7NVVUl_40qWen4acAj_tmY6vSY9ISuTyux4JBcAKtlic5jVEm8-yinkv9CSyIuxzm8t3ILZU27KBZ-uCILHEUNSNmiPi0fNh6c1Gmp5v9uaIgt5SSn1wurAvcwYghdzLk1wAc29q_ns3Aw54ubFzWqluQvzChDLfYDFMYLAXPrvJv8uQ
    // timestamp: 638133466078326141
    public void testProofKeys(String wopiRequestUrl,
                              String proofKey,
                              String oldProofKey,
                              String accessToken,
                              String timestamp) {
        try {
            // get the discovery xml from host
            var wopiDiscovery = wopiService.getDiscoveryXML();
            // strWopiDiscoveryModulus: vQyKrum6wrsZ7P2aVYPYPzIJEMUIf+K6bc0Bt3nDRpNCOkR4M8NvIUOMXNKqMFQgLjIOuTNais5Ujb4CxXs1ETW2fxF4lWyeRIQSPSwvNDVFhyyqw3cNwLA17topEdyWmFWbKFStILqS39u5QHfqc+ATrMaRafkyLuj8XyVxarv3zbWmDitiI9xwn7R86N4vuFN8QR0ge2tHIgqx3qtDSpLuRM3zM27Osxtro92pthDJyGj+e0q+2Qwv9XexfjVm8KvdDE3oVIBep8/bSUY52pHJddotblKeNhTyIzz9uJ7b8BZbT1Gg/l1QWVXDfEa5crrdhgeG0Y9iJEhbXIY6TQ==
            String strWopiDiscoveryModulus = wopiDiscovery.getProofKey().getModulus();

            // strWopiDiscoveryExponent: AQAB
            String strWopiDiscoveryExponent = wopiDiscovery.getProofKey().getExponent();

            // strWopiDiscoveryOldModulus: vQyKrum6wrsZ7P2aVYPYPzIJEMUIf+K6bc0Bt3nDRpNCOkR4M8NvIUOMXNKqMFQgLjIOuTNais5Ujb4CxXs1ETW2fxF4lWyeRIQSPSwvNDVFhyyqw3cNwLA17topEdyWmFWbKFStILqS39u5QHfqc+ATrMaRafkyLuj8XyVxarv3zbWmDitiI9xwn7R86N4vuFN8QR0ge2tHIgqx3qtDSpLuRM3zM27Osxtro92pthDJyGj+e0q+2Qwv9XexfjVm8KvdDE3oVIBep8/bSUY52pHJddotblKeNhTyIzz9uJ7b8BZbT1Gg/l1QWVXDfEa5crrdhgeG0Y9iJEhbXIY6TQ==
            String strWopiDiscoveryOldModulus = wopiDiscovery.getProofKey().getOldModulus();

            // strWopiDiscoveryOldExponent: AQAB
            String strWopiDiscoveryOldExponent = wopiDiscovery.getProofKey().getOldExponent();

            // url before : http://mywopi.domain.lu/wopi/files/20fc8815-9158-49f9-87d6-de732ed344bb
            wopiRequestUrl = wopiRequestUrl.replace("http", "https");

            wopiRequestUrl = wopiRequestUrl + "?access_token=" + accessToken;
            byte[] expectedProofArray = getExpectedProofBytes( wopiRequestUrl, accessToken, timestamp );

            /** Verify proofKey validation in 3 scenarios:
             The X-WOPI-Proof value using the current public key
             The X-WOPI-ProofOld value using the current public key
             The X-WOPI-Proof value using the old public key
             */
            System.out.println( "VERIFIED = " + verifyProofKey(
                    strWopiDiscoveryModulus, strWopiDiscoveryExponent, proofKey, expectedProofArray ) );
            System.out.println( "VERIFIED = " + verifyProofKey(
                    strWopiDiscoveryModulus, strWopiDiscoveryExponent, oldProofKey, expectedProofArray ) );
            System.out.println( "VERIFIED = " + verifyProofKey(
                    strWopiDiscoveryOldModulus, strWopiDiscoveryOldExponent, proofKey, expectedProofArray ) );
        } catch (ExecutionException e) {
            log.info("Exception" + e);
        }

        /** OUTPUT !!
        VERIFIED = false
        VERIFIED = false
        VERIFIED = false
         */
    }


    /**
     * @param strWopiProofKey    - Proof key from REST header
     * @param expectedProofArray - Byte Array from Specification -- Contains querystring, time and accesskey combined by defined algorithm in spec
     *                           4 bytes that represent the length, in bytes, of the access_token on the request.
     *                           The access_token.
     *                           4 bytes that represent the length, in bytes, of the full URL of the WOPI request, including any query string parameters.
     *                           The WOPI request URL in all uppercase. All query string parameters on the request URL should be included.
     *                           4 bytes that represent the length, in bytes, of the X-WOPI-TimeStamp value.
     *                           The X-WOPI-TimeStamp value.
     * @return
     * @throws Exception
     */
    public static boolean verifyProofKey( String strModulus, String strExponent,
                                          String strWopiProofKey, byte[] expectedProofArray ) {
        try{
            PublicKey publicKey = getPublicKey( strModulus, strExponent );

            Signature verifier = Signature.getInstance( "SHA256withRSA" );
            verifier.initVerify( publicKey );
            verifier.update( expectedProofArray );

            final byte[] signedProof = DatatypeConverter.parseBase64Binary( strWopiProofKey );

            return verifier.verify( signedProof );
        }
        catch (Exception e)
        {
            log.info("Exception:" + e.toString());
            return false;
        }

    }


    /**
     * Gets a public RSA Key using WOPI Discovery Modulus and Exponent for PKI Signed Validation
     *
     * @param modulus
     * @param exponent
     * @return
     * @throws Exception
     */
    private static RSAPublicKey getPublicKey(String modulus, String exponent )
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeySpecException {
        BigInteger mod = new BigInteger( 1, DatatypeConverter.parseBase64Binary( modulus ) );
        BigInteger exp = new BigInteger( 1, DatatypeConverter.parseBase64Binary( exponent ) );
        KeyFactory factory = KeyFactory.getInstance( "RSA" );
        KeySpec ks = new RSAPublicKeySpec( mod, exp );

        return (RSAPublicKey) factory.generatePublic( ks );
    }


    /**
     * Generates expected proof
     *
     * @param url
     * @param accessToken
     * @param timestampStr
     * @return
     */
    private static byte[] getExpectedProofBytes( String url, final String accessToken, final String timestampStr )
    {

        final byte[] accessTokenBytes = accessToken.getBytes( StandardCharsets.UTF_8 );

        var upperCaseUrl = url.toUpperCase(Locale.ROOT);
        // HTTPS://WOPI.FINDL.LU/WOPI/FILES/20FC8815-9158-49F9-87D6-DE732ED344BB?ACCESS_TOKEN=EYJHBGCIOIJSUZI1NIISINR5CCIGOIAISLDUIIWIA2LKIIA6ICJOTZNOVVH5DGYTTVR1VTVHZVNNX0LVCWTYMVP0BVVAVEFUS2D4T25QR09JIN0.EYJLEHAIOJE2NZC3NDKXMJMSIMLHDCI6MTY3NZC0ODIYMYWIANRPIJOIZJFKZDBLODKTMJBHYS00MJE3LTLHY2ETYZBHNZM3YMI4YTZMIIWIAXNZIJOIAHR0CHM6LY9HDXROLMZPBMRSLMX1L2F1DGGVCMVHBG1ZL2VKBXMTDJIILCJHDWQIOIJHY2NVDW50IIWIC3VIIJOINWRHMMQ1NJATZMMXMS00NDDLLWEZN2UTMZYXYMIZMTU3OTRKIIWIDHLWIJOIQMVHCMVYIIWIYXPWIJOIYW5NDWXHCI1LZG1ZIIWIC2VZC2LVBL9ZDGF0ZSI6IJK3ODNIMTY2LWM1ZTCTNGRLNS05YMJILTBLNWYWYTKWMZU3OSISIMFJCII6IJEILCJHBGXVD2VKLW9YAWDPBNMIOLSIAHR0CHM6LY9IDWNRBGUUZMLUZGWUBHUVIIWIAHR0CDOVL2XVY2FSAG9ZDDO4MDGXIIWIAHR0CHM6LY9LZG1ZLMZPBMRSLMX1IIWIAHR0CHM6LY9KB2NZLMF0B3OTZGLNAXRHBC5SDSISIMH0DHA6LY8XMJCUMC4WLJE6ODA4MSISIMH0DHA6LY9SB2NHBGHVC3Q6NDIWMCJDLCJYZWFSBV9HY2NLC3MIONSICM9SZXMIOLSIZGVMYXVSDC1YB2XLCY1LZG1ZLXYYIIWIB2ZMBGLUZV9HY2NLC3MILCJ1BWFFYXV0AG9YAXPHDGLVBIJDFSWICMVZB3VYY2VFYWNJZXNZIJP7IMFJY291BNQIONSICM9SZXMIOLSIBWFUYWDLLWFJY291BNQILCJTYW5HZ2UTYWNJB3VUDC1SAW5RCYISINZPZXCTCHJVZMLSZSJDFX0SINNJB3BLIJOIZW1HAWWGCHJVZMLSZSISIMVTYWLSX3ZLCMLMAWVKIJP0CNVLLCJUYW1LIJOIQ2HVDWFPYIBFTE1BS0HMT1VLIIWICHJLZMVYCMVKX3VZZXJUYW1LIJOIY2HVDWFPYI5LBG1HA2HSB3VRQGF0B3OTZGLNAXRHBC5SDSISIMDPDMVUX25HBWUIOIJDAG91YWLIIIWIZMFTAWX5X25HBWUIOIJFTE1BS0HMT1VLIIWIZW1HAWWIOIJJAG91YWLILMVSBWFRAGXVDWTAYXRVEI1KAWDPDGFSLMX1IN0.J9L_BZMZT-BDKJIKPQBEYOHKK37SDHEXL_ZUIGBHCUDBXL8ZCBGDABLKFOA1C3M2HJSME59_TL_UOYCUZJQZS5HP8RSCOJRH5MEI1FMHDXGVJMHTFDNDN9JRJFKC1HGDEXO4YD7KHSKXKKXEO8OP5E8JSHO5YONVRWVFFJPJSL5RTYYH0JAYJGBQR0_K5QV5J0-KSRM7V9VEMQ8NCIEB-H4TH1JOVIMMTAAKGID6R9OXQFYPNPR6_VJRN_RN2SLKIXLMG0_QG_QWCTXMJH3MQVTNC1FNCV90O2FMUXH33V5FLUK_HGX4AFGBZQ7FBOVVQKU7-JFFX9_KXM8XTHDBLA

        final byte[] hostUrlBytes = upperCaseUrl.getBytes( StandardCharsets.UTF_8 );

        final Long timestamp = Long.valueOf( timestampStr );

        final ByteBuffer byteBuffer = ByteBuffer.allocate(
                4 + accessTokenBytes.length + 4 + hostUrlBytes.length + 4 + 8 );
        byteBuffer.putInt( accessTokenBytes.length );
        byteBuffer.put( accessTokenBytes );
        byteBuffer.putInt( hostUrlBytes.length );
        byteBuffer.put( hostUrlBytes );
        byteBuffer.putInt( 8 );
        byteBuffer.putLong( timestamp );

        return byteBuffer.array();
    }
}
