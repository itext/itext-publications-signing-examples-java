package com.itextpdf.signingexamples.jce.utimaco;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.junit.jupiter.api.Test;

import CryptoServerAPI.CryptoServerException;
import CryptoServerJCE.CryptoServerProvider;

class TestJceAccess {
    @Test
    void test() throws IOException, CryptoServerException, GeneralSecurityException {
        String config = "Device = 3001@127.0.0.1\n"
                + "DefaultUser = JCE\n"
                + "KeyGroup = JCE";
        CryptoServerProvider provider = new CryptoServerProvider(new ByteArrayInputStream(config.getBytes()));
        Security.addProvider(provider);
        provider.loginPassword("JCE","5678");

        KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
        ks.load(null, null);

        Enumeration<String> aliases = ks.aliases();
        assert aliases != null;
        assert aliases.hasMoreElements();
        String alias = aliases.nextElement();
        System.out.printf("Alias name: %s\n", alias);

        PrivateKey pk = (PrivateKey) ks.getKey(alias, "5678".toCharArray());
        assert pk != null;

        Certificate[] chain = ks.getCertificateChain(alias);
        assert chain != null;
        assert 0 != chain.length;
        for (Certificate certificate : chain)
            if (certificate instanceof X509Certificate)
                System.out.printf("Subject: %s\n", ((X509Certificate) certificate).getSubjectDN());
    }

}
