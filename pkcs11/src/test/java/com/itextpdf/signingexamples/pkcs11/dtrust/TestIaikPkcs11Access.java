package com.itextpdf.signingexamples.pkcs11.dtrust;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Properties;

import org.junit.jupiter.api.Test;

import iaik.pkcs.pkcs11.provider.IAIKPkcs11;

/**
 * This test class executes some simple tests addressing the
 * D-Trust card via the Nexus Personal PKCS#11 driver and the
 * IAIK Java PKCS#11 security provider to retrieve key handles
 * and certificates.
 * 
 * @author mkl
 */
class TestIaikPkcs11Access {
    @Test
    void testAccessKeyAndCertificate() throws GeneralSecurityException, IOException {
        Properties properties = new Properties();
        properties.setProperty("PKCS11_NATIVE_MODULE", "c:/Program Files (x86)/Personal/bin64/personal64.dll");
        properties.setProperty("SLOT_ID", "1");
        IAIKPkcs11 provider = new IAIKPkcs11(properties);
        Security.addProvider(provider);

        KeyStore tokenKeyStore = KeyStore.getInstance("PKCS11KeyStore");
        tokenKeyStore.load(null, null);

        Enumeration<String> aliases = tokenKeyStore.aliases();
        assert aliases != null;
        assert aliases.hasMoreElements();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.printf("Alias name: %s\n", alias);
            Key key = tokenKeyStore.getKey(alias, "12345678".toCharArray());
            if (key instanceof PrivateKey) {
                System.out.print("  has private key: true\n");
            } else {
                System.out.print("  has private key: false\n");
                continue;
            }

            Certificate[] chain = tokenKeyStore.getCertificateChain(alias);
            assert chain != null;
            assert 0 != chain.length;
            for (Certificate certificate : chain)
                if (certificate instanceof X509Certificate)
                    System.out.printf("Subject: %s\n", ((X509Certificate) certificate).getSubjectDN());
        }
    }
}
