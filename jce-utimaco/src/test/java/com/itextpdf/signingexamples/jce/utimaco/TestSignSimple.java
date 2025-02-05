package com.itextpdf.signingexamples.jce.utimaco;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.RSASSAPSSMechanismParams;

import CryptoServerAPI.CryptoServerException;
import CryptoServerJCE.CryptoServerProvider;

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

    final static String CONFIG =
            "Device = 3001@127.0.0.1\n"
            + "DefaultUser = JCE\n"
            + "KeyGroup = JCE";

    /**
     * Test using the custom {@link UtimacoJceSignature} implementation
     * of {@link IExternalSignature} to create a RSA signature with PKCS#1 v1.5
     * padding.
     */
    @Test
    void testSignSimpleUtimacoJceSignature() throws IOException, CryptoServerException, GeneralSecurityException {
        UtimacoJceSignature signature = new UtimacoJceSignature(new ByteArrayInputStream(CONFIG.getBytes()))
                .select(null, "5678".toCharArray()).setDigestAlgorithmName("SHA256");

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-utimaco-signed-simple-specific.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            IExternalDigest externalDigest = new BouncyCastleDigest();
            pdfSigner.signDetached(externalDigest, signature, signature.getChain(), null, null, null, 0, CryptoStandard.CMS);
        }
    }

    /**
     * Test using the custom {@link UtimacoJceSignature} implementation
     * of {@link IExternalSignature} to create a RSA signature with PKCS#1 v1.5
     * padding.
     */
    @Test
    void testSignSimpleUtimacoJceSignaturePss() throws IOException, CryptoServerException, GeneralSecurityException {
        UtimacoJceSignature signature = new UtimacoJceSignature(new ByteArrayInputStream(CONFIG.getBytes()))
                .select(null, "5678".toCharArray()).setDigestAlgorithmName("SHA256")
                .with(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));;

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-utimaco-signed-simple-specific-pss.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            IExternalDigest externalDigest = new BouncyCastleDigest();
            pdfSigner.signDetached(externalDigest, signature, signature.getChain(), null, null, null, 0, CryptoStandard.CMS);
        }
    }

    /**
     * Test using the iText {@link PrivateKeySignature} implementation
     * of {@link IExternalSignature} to create a RSA signature with PKCS#1 v1.5
     * padding.
     */
    @Test
    void testSignSimpleGeneric() throws NumberFormatException, IOException, CryptoServerException, GeneralSecurityException {
        char[] pin = "5678".toCharArray();
        CryptoServerProvider provider = new CryptoServerProvider(new ByteArrayInputStream(CONFIG.getBytes()));
        Security.removeProvider(provider.getName());
        Security.addProvider(provider);

        KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
        ks.load(null, pin);

        Enumeration<String> aliases = ks.aliases();
        assert aliases.hasMoreElements();
        String alias = aliases.nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, pin);
        assert pk != null;
        Certificate[] chain = ks.getCertificateChain(alias);
        assert chain != null;

        IExternalSignature signature = new PrivateKeySignature(pk, "SHA256", provider.getName());
        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-utimaco-signed-simple-generic.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            IExternalDigest externalDigest = new BouncyCastleDigest();
            pdfSigner.signDetached(externalDigest, signature, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    /**
     * <p>
     * Test using the iText {@link PrivateKeySignature} implementation
     * of {@link IExternalSignature} to create a RSASSA-PSS signature.
     * </p><p>
     * This code overrides {@link PrivateKeySignature#sign(byte[])} for two work-arounds.
     * </p><p>
     * On one hand the Utimaco JCE CryptoServer provider expects RSASSA-PSS signatures to
     * be created using "SHAXXXwithRSA" as algorithm name, recognizing the PSS nature by
     * the set parameters. It does reject "SHAXXXwithRSASSA-PSS" and similar names showing
     * the PSS nature already in the signature algorithm name. iText only tries algorithm
     * names mentioning PSS.
     * </p><p>
     * On the other hand it expects the hash algorithm in the {@link PSSParameterSpec} (the
     * first constructor parameter) to be written in a form with a dash, e.g. "SHA-256".
     * iText normalizes to the Java default without a dash, e.g. "SHA256".
     * </p>
     */
    @Test
    void testSignSimpleGenericPss() throws NumberFormatException, IOException, CryptoServerException, GeneralSecurityException {
        char[] pin = "5678".toCharArray();
        CryptoServerProvider provider = new CryptoServerProvider(new ByteArrayInputStream(CONFIG.getBytes()));
        Security.removeProvider(provider.getName());
        Security.addProvider(provider);

        KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
        ks.load(null, pin);

        Enumeration<String> aliases = ks.aliases();
        assert aliases.hasMoreElements();
        String alias = aliases.nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, pin);
        assert pk != null;
        Certificate[] chain = ks.getCertificateChain(alias);
        assert chain != null;

        String digestName = "SHA-256";
        IExternalSignature signature = new PrivateKeySignature(pk, digestName, "RSASSA-PSS", provider.getName(), RSASSAPSSMechanismParams.createForDigestAlgorithm(digestName)) {
            @Override
            public byte[] sign(byte[] message) throws GeneralSecurityException {
                Signature sig = Signature.getInstance("SHA256withRSA", provider);

                MGF1ParameterSpec mgf1Spec = new MGF1ParameterSpec(digestName);
                PSSParameterSpec spec = new PSSParameterSpec(digestName, "MGF1", mgf1Spec, 32, RSASSAPSSMechanismParams.DEFAULT_TRAILER_FIELD);
                sig.setParameter(spec);

                sig.initSign(pk);
                sig.update(message);
                return sig.sign();
            }
        };
        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-utimaco-signed-simple-generic-pss.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            IExternalDigest externalDigest = new BouncyCastleDigest();
            pdfSigner.signDetached(externalDigest, signature, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    /**
     * Test using the custom {@link UtimacoJceSignatureContainer} implementation
     * of {@link IExternalSignature} to create a RSA signature with PKCS#1 v1.5
     * padding.
     */
    @Test
    void testSignSimpleUtimacoJceSignatureContainerRsaPkcs1() throws IOException, CryptoServerException, GeneralSecurityException {
        CryptoServerProvider provider = new CryptoServerProvider(new ByteArrayInputStream(CONFIG.getBytes()));
        Security.removeProvider(provider.getName());
        Security.addProvider(provider);

        UtimacoJceSignatureContainer signature = new UtimacoJceSignatureContainer(
                provider, PdfName.Adbe_pkcs7_detached)
                .select(null, "5678".toCharArray()).with("SHA256withRSA", null);

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-utimaco-signed-simple-container-specific-pkcs1.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            pdfSigner.signExternalContainer(signature, 8192);
        }
    }

    /**
     * Test using the custom {@link UtimacoJceSignatureContainer} implementation
     * of {@link IExternalSignature} to create a RSASSA-PSS signature.
     */
    @Test
    void testSignSimpleUtimacoJceSignatureContainerRsaSsaPss() throws IOException, CryptoServerException, GeneralSecurityException {
        CryptoServerProvider provider = new CryptoServerProvider(new ByteArrayInputStream(CONFIG.getBytes()));
        Security.removeProvider(provider.getName());
        Security.addProvider(provider);

        UtimacoJceSignatureContainer signature = new UtimacoJceSignatureContainer(
                provider, PdfName.Adbe_pkcs7_detached)
                .select(null, "5678".toCharArray()).with("SHA256withRSA", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-utimaco-signed-simple-container-specific-pss.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            pdfSigner.signExternalContainer(signature, 8192);
        }
    }
}
