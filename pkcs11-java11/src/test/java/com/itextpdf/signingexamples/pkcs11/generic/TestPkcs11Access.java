package com.itextpdf.signingexamples.pkcs11.generic;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

/**
 * This test class executes some simple tests addressing the
 * PKCS11 device to retrieve key handles and certificates.
 * The {@link TestEnvironment} utility is used to retrieve
 * parameters for accessing the device.
 * 
 * @author mkl
 */
class TestPkcs11Access {

    @Test
    void testAccessKeyAndCertificate() throws GeneralSecurityException, IOException {
        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider(providerBC);

        String config = TestEnvironment.getPkcs11Config();

        Provider p = Security.getProvider("SunPKCS11");
        assert p!= null;

        Provider providerPKCS11 = p.configure(config);
        assert providerPKCS11!= null;
        Security.addProvider(providerPKCS11);
        System.out.printf("Provider name: %s\n", providerPKCS11.getName());

        KeyStore ks = KeyStore.getInstance("PKCS11", providerPKCS11);
        assert ks != null;
        ks.load(null, TestEnvironment.getPkcs11Pin());

        Enumeration<String> aliases = ks.aliases();
        assert aliases != null;
        assert aliases.hasMoreElements();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.printf("Alias name: %s\n", alias);
            PrivateKey pk = (PrivateKey) ks.getKey(alias, TestEnvironment.getPkcs11Pin());
            System.out.printf("  has private key: %s\n", (pk != null));
            if (pk == null)
                continue;

            Certificate[] chain = ks.getCertificateChain(alias);
            assert chain != null;
            assert 0 != chain.length;
            for (Certificate certificate : chain)
                if (certificate instanceof X509Certificate)
                    System.out.printf("Subject: %s\n", ((X509Certificate) certificate).getSubjectDN());
        }
    }
}
