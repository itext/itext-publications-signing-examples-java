package com.itextpdf.signingexamples.pkcs11.utimaco;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Test;

import com.itextpdf.signingexamples.pkcs11.BaseSignSimple;

/**
 * <p>
 * This test class signs a PDF file using {@link BaseSignSimple}
 * with variables set to access an Utimaco Simulator as
 * configured and initialized on the original development
 * machine.
 * </p>
 * <p>
 * Please remember to set the <code>CS_PKCS11_R2_CFG</code>
 * environment variable to point to the Utimaco configuration
 * file <code>cs_pkcs11_R2.cfg</code>.
 * </p>
 * 
 * @author mkl
 */
class TestSignSimple extends BaseSignSimple {
    @Test
    void test() throws IOException, GeneralSecurityException {
        config = "--name = Utimaco\n"
                + "library = c:/Program Files/Utimaco/CryptoServer/Lib/cs_pkcs11_R2.dll\n"
                + "slot = 0\n";
        alias = null;
        pin = "123456".toCharArray();
        result = new File(RESULT_FOLDER, "circles-pkcs11-signed-simple-utimaco.pdf");
        testSignSimple();
    }

    // Beware, you may be subject of https://bugs.openjdk.org/browse/JDK-8232950 and
    // get an InvalidKeyException: "RSA key must be at least 512 bytes".
    // The fix of that bug has been backported to Oracle Java 1.8 in u391, see JDK-8310185.
    // In OpenJdk 8, on the other hand, it already has been backported in u352, see JDK-8292875.
    // In Amazon Corretto 1.8 u382, for example, tests show that the bug does not occur anymore.
    @Test
    void testWithPss() throws IOException, GeneralSecurityException {
        config = "--name = Utimaco\n"
                + "library = \"c:/Program Files/Utimaco/CryptoServer/Lib/cs_pkcs11_R2.dll\"\n"
                + "slot = 0\n";
        alias = null;
        pin = "123456".toCharArray();
        result = new File(RESULT_FOLDER, "circles-pkcs11-signed-simple-utimaco-pss.pdf");
        testSignSimpleWithPss();
    }
}
