package com.itextpdf.signingexamples.csc;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collections;
import java.util.List;

import com.itextpdf.bouncycastleconnector.BouncyCastleFactoryCreator;
import com.itextpdf.commons.bouncycastle.IBouncyCastleFactory;
import com.itextpdf.kernel.crypto.DigestAlgorithms;
import com.itextpdf.kernel.xmp.impl.Base64;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.ISignatureMechanismParams;
import com.itextpdf.signatures.SignatureMechanisms;

import fi.methics.laverca.csc.CscClient;
import fi.methics.laverca.csc.json.credentials.CscCredentialsAuthorizeResp;
import fi.methics.laverca.csc.json.credentials.CscCredentialsInfoResp;
import fi.methics.laverca.csc.json.signatures.CscSignHashResp;

/**
 * @author mkl
 */
public class LavercaCscSignature implements IExternalSignature {
    /** The Laverca CSC client. */
    final CscClient client;

    /** The Laverca CSC client. */
    final String credentialID;

    /** The certificate chain. */
    Certificate[] chain;

    /** The signature algorithm OID. */
    String algorithmOid;

    public LavercaCscSignature(CscClient client, String credentialID, String algorithm) throws GeneralSecurityException {
        this.client = client;
        this.credentialID = credentialID;

        CscCredentialsInfoResp credentialInfo = client.getCredentialInfo(credentialID);

        List<String> certificateStrings = credentialInfo.cert.certificates;
        chain = new Certificate[certificateStrings.size()];
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        for (int i = 0; i < certificateStrings.size(); i++) {
            String certificateString = certificateStrings.get(i);
            byte[] certificateBytes = Base64.decode(certificateString.getBytes());
            chain[i] = certificateFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
        }

        IBouncyCastleFactory BOUNCY_CASTLE_FACTORY = BouncyCastleFactoryCreator.getFactory();
        String algorithmOid = BOUNCY_CASTLE_FACTORY.getAlgorithmOid(algorithm);
        if (algorithmOid == null)
            algorithmOid = algorithm;
        if (credentialInfo.key.algo.contains(algorithmOid))
            this.algorithmOid = algorithmOid;
    }

    @Override
    public String getDigestAlgorithmName() {
        return DigestAlgorithms.getDigest(algorithmOid);
    }

    @Override
    public String getSignatureAlgorithmName() {
        return SignatureMechanisms.getAlgorithm(algorithmOid);
    }

    @Override
    public ISignatureMechanismParams getSignatureMechanismParameters() {
        // TODO Add RSASSA-PSS support
        return null;
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        MessageDigest messageDigest = new BouncyCastleDigest().getMessageDigest(getDigestAlgorithmName());
        byte[] hash = messageDigest.digest(message);
        String base64Hash = new String(Base64.encode(hash));

        CscCredentialsInfoResp credentialInfo = client.getCredentialInfo(credentialID);
        CscCredentialsAuthorizeResp authorize = null;
        if (credentialInfo.isScal2()) {
            authorize = client.authorize(credentialID, Collections.singletonList(base64Hash));
        } else {
            authorize = client.authorize(credentialID);
        }

        CscSignHashResp signhash = client.signHash(credentialID, authorize, Collections.singletonList(base64Hash), algorithmOid, null);

        return Base64.decode(signhash.signatures.get(0).getBytes());
    }

    public Certificate[] getChain() {
        return chain;
    }
}
