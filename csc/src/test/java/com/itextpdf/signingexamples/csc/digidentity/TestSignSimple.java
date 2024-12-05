package com.itextpdf.signingexamples.csc.digidentity;

import java.awt.Desktop;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.itextpdf.io.source.ByteArrayOutputStream;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;
import com.itextpdf.signingexamples.csc.LavercaCscSignature;

import fi.methics.laverca.csc.CscClient;
import fi.methics.laverca.csc.json.credentials.CscCredentialsListResp;

/**
 * @author mkl
 */
class TestSignSimple {
    final static File RESULT_FOLDER = new File("target/test-outputs", "signature");

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
    }

    public final static String CLIENT = "CLIENT_NAME";
    public final static String SECRET = "CLIENT_SECRET";
    public final static String SCOPE = "CLIENT_SCOPE";

    @Test
    void test() throws IOException, GeneralSecurityException, URISyntaxException, IllegalAccessException, NoSuchFieldException {
        Authorization authorization = new Authorization()
                .withScope(SCOPE)
                .withClient(CLIENT)
                .withSecret(SECRET);
        String qrCodeUri = authorization.retrieveQrCodeUri();
        Desktop.getDesktop().browse(new URI(qrCodeUri));
        authorization.pollAuthorization(3000);
        String cscToken = authorization.retrieveCscToken();
        CscClient client = new CscClient.Builder().withBaseUrl(Authorization.CSC_API_BASE_URL)
                .withTrustInsecureConnections(true)
                .build();
        Authorization.injectCscToken(client, cscToken);;
        CscCredentialsListResp credentials = client.listCredentials();

        LavercaCscSignature signature = new LavercaCscSignature(client, credentials.credentialIDs.get(0), "SHA256withRSA");

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-csc-digidentity-signed-simple.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            IExternalDigest externalDigest = new BouncyCastleDigest();
            pdfSigner.signDetached(externalDigest, signature, signature.getChain(), null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    void testSignTwice() throws IOException, GeneralSecurityException, URISyntaxException, IllegalAccessException, NoSuchFieldException {
        Authorization authorization = new Authorization()
                .withScope(SCOPE)
                .withClient(CLIENT)
                .withSecret(SECRET);
        String qrCodeUri = authorization.retrieveQrCodeUri();
        Desktop.getDesktop().browse(new URI(qrCodeUri));
        authorization.pollAuthorization(2000);
        String cscToken = authorization.retrieveCscToken();
        CscClient client = new CscClient.Builder().withBaseUrl(Authorization.CSC_API_BASE_URL)
                .withTrustInsecureConnections(true)
                .build();
        Authorization.injectCscToken(client, cscToken);;
        CscCredentialsListResp credentials = client.listCredentials();

        LavercaCscSignature signature = new LavercaCscSignature(client, credentials.credentialIDs.get(0), "SHA256withRSA");
        ByteArrayOutputStream intermediary = new ByteArrayOutputStream();
        IExternalDigest externalDigest = new BouncyCastleDigest();

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource)) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, intermediary, new StampingProperties().useAppendMode());
            pdfSigner.signDetached(externalDigest, signature, signature.getChain(), null, null, null, 0, CryptoStandard.CMS);
        }

        try (   InputStream resource = new ByteArrayInputStream(intermediary.toByteArray());
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-csc-digidentity-signed-simple-twice.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());
            pdfSigner.signDetached(externalDigest, signature, signature.getChain(), null, null, null, 0, CryptoStandard.CMS);
        }
    }
}
