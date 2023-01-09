package com.itextpdf.signingexamples.pkcs11;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertificateException;

import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalSignature;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This {@link IExternalSignature} implementation is based on the
 * <a href="https://jce.iaik.tugraz.at/products/core-crypto-toolkits/pkcs11-wrapper/">
 * IAIK PKCS#11 Wrapper</a>
 * 
 * @author mkl
 */
public class Pkcs11WrapperSignature extends Pkcs11WrapperKeyAndCertificate implements IExternalSignature {
    String signatureAlgorithmName;
    String digestAlgorithmName;

    public Pkcs11WrapperSignature(String libraryPath, long slotId) throws IOException, TokenException {
        super(libraryPath, slotId);
    }

    public Pkcs11WrapperSignature select(String alias, String certLabel, char[] pin) throws TokenException, CertificateException {
        super.select(alias, certLabel, pin);
        if (Key.KeyType.RSA.equals(keyType)) {
            signatureAlgorithmName = "RSA";
        } else if (Key.KeyType.DSA.equals(keyType)) {
            signatureAlgorithmName = "DSA";
        } else if (Key.KeyType.ECDSA.equals(keyType)) {
            signatureAlgorithmName = "ECDSA";
        } else {
            signatureAlgorithmName = null;
        }

        return this;
    }

    @Override
    public String getSignatureAlgorithmName() {
        return signatureAlgorithmName;
    }

    @Override
    public String getDigestAlgorithmName() {
        return digestAlgorithmName;
    }

    public Pkcs11WrapperSignature setDigestAlgorithmName(String digestAlgorithmName) {
        this.digestAlgorithmName = DigestAlgorithms.getDigest(DigestAlgorithms.getAllowedDigest(digestAlgorithmName));
        return this;
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        long mechanismId;
        switch(signatureAlgorithmName) {
        case "DSA":
            switch(digestAlgorithmName) {
            case "SHA1":
                mechanismId = PKCS11Constants.CKM_DSA_SHA1;
                break;
            case "SHA224":
                mechanismId = PKCS11Constants.CKM_DSA_SHA224;
                break;
            case "SHA256":
                mechanismId = PKCS11Constants.CKM_DSA_SHA256;
                break;
            case "SHA384":
                mechanismId = PKCS11Constants.CKM_DSA_SHA384;
                break;
            case "SHA512":
                mechanismId = PKCS11Constants.CKM_DSA_SHA512;
                break;
            default:
                throw new InvalidAlgorithmParameterException("Not supported: " + digestAlgorithmName + "with" + signatureAlgorithmName);
            }
        case "ECDSA":
            switch (digestAlgorithmName)
            {
            case "SHA1":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA1;
                break;
            case "SHA224":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA224;
                break;
            case "SHA256":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA256;
                break;
            case "SHA384":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA384;
                break;
            case "SHA512":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA512;
                break;
            default:
                throw new InvalidAlgorithmParameterException("Not supported: " + digestAlgorithmName + "with" + signatureAlgorithmName);
            }
            break;
        case "RSA":
            switch (digestAlgorithmName)
            {
            case "SHA1":
                mechanismId = PKCS11Constants.CKM_SHA1_RSA_PKCS;
                break;
            case "SHA224":
                mechanismId = PKCS11Constants.CKM_SHA224_RSA_PKCS;
                break;
            case "SHA256":
                mechanismId = PKCS11Constants.CKM_SHA256_RSA_PKCS;
                break;
            case "SHA384":
                mechanismId = PKCS11Constants.CKM_SHA384_RSA_PKCS;
                break;
            case "SHA512":
                mechanismId = PKCS11Constants.CKM_SHA512_RSA_PKCS;
                break;
            default:
                throw new InvalidAlgorithmParameterException("Not supported: " + digestAlgorithmName + "with" + signatureAlgorithmName);
            }
            break;
        default:
            throw new InvalidAlgorithmParameterException("Not supported: " + digestAlgorithmName + "with" + signatureAlgorithmName);

        }

        Mechanism signatureMechanism = Mechanism.get(mechanismId);
        try {
            session.signInit(signatureMechanism, privateKey);
            return session.sign(message);
        } catch (TokenException e) {
            throw new GeneralSecurityException(e);
        } 
    }
}
