package com.itextpdf.signingexamples.jce.utimaco;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Enumeration;

import com.itextpdf.bouncycastleconnector.BouncyCastleFactoryCreator;
import com.itextpdf.commons.bouncycastle.IBouncyCastleFactory;
import com.itextpdf.commons.bouncycastle.asn1.IASN1ObjectIdentifier;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.ISignatureMechanismParams;
import com.itextpdf.signatures.RSASSAPSSMechanismParams;

import CryptoServerAPI.CryptoServerException;
import CryptoServerJCE.CryptoServerProvider;

/**
 * @author mkl
 */
public class UtimacoJceSignature implements IExternalSignature {
    /** The alias. */
    String alias;

    /** The private key object. */
    PrivateKey pk;

    /** The certificate chain. */
    Certificate[] chain;

    /** The digest algorithm. */
    String digestAlgorithmName;

    /** The signature algorithm (obtained from the private key) */
    String signatureAlgorithmName;

    /** The parameters of the fill, explicitly given signature algorithm. */
    AlgorithmParameterSpec fullSignatureAlgorithmParamSpec;

    /** The security provider */
    final CryptoServerProvider provider;

    public UtimacoJceSignature(File utimacoConfigFile) throws IOException, CryptoServerException {
        provider = new CryptoServerProvider(utimacoConfigFile.getAbsolutePath());
        Security.addProvider(provider);
    }

    public UtimacoJceSignature(InputStream utimacoConfig) throws IOException, CryptoServerException {
        provider = new CryptoServerProvider(utimacoConfig);
        Security.addProvider(provider);
    }

    public UtimacoJceSignature(CryptoServerProvider utimacoProvider) {
        provider = utimacoProvider;
        Security.addProvider(provider);
    }

    public UtimacoJceSignature select(String alias, char[] pin) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
        ks.load(null, pin);

        boolean found = false;
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String thisAlias = aliases.nextElement();
            if (alias == null || alias.equals(thisAlias)) {
                PrivateKey thisPk = (PrivateKey) ks.getKey(thisAlias, pin);
                if (thisPk == null)
                    continue;
                Certificate[] thisChain = ks.getCertificateChain(thisAlias);
                if (thisChain == null)
                    continue;

                found = true;
                pk = thisPk;
                chain = thisChain;
                this.alias = thisAlias;
                break;
            }
        }

        if (found) {
            String algorithm = pk.getAlgorithm();
            signatureAlgorithmName = "EC".equals(algorithm) ? "ECDSA" : algorithm;
        } else {
            pk = null;
            chain = null;
            this.alias = null;
            signatureAlgorithmName = null;
        }

        return this;
    }

    public UtimacoJceSignature with(AlgorithmParameterSpec paramSpec) {
        this.fullSignatureAlgorithmParamSpec = paramSpec;
        return this;
    }

    public String getAlias() {
        return alias;
    }

    public Certificate[] getChain() {
        return chain;
    }

    @Override
    public String getSignatureAlgorithmName() {
        if ("RSA".equals(signatureAlgorithmName) && (fullSignatureAlgorithmParamSpec instanceof PSSParameterSpec))
            return "RSASSA-PSS";
        return signatureAlgorithmName;
    }

    @Override
    public String getDigestAlgorithmName() {
        return digestAlgorithmName;
    }

    public UtimacoJceSignature setDigestAlgorithmName(String digestAlgorithmName) {
        this.digestAlgorithmName = DigestAlgorithms.getDigest(DigestAlgorithms.getAllowedDigest(digestAlgorithmName));
        return this;
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        String algorithm = digestAlgorithmName + "with" + signatureAlgorithmName; // explicitly don't add "SSA-PSS" or "andMGF1"
        Signature sig = Signature.getInstance(algorithm, provider);
        sig.initSign(pk);
        if (fullSignatureAlgorithmParamSpec != null)
            sig.setParameter(fullSignatureAlgorithmParamSpec);
        sig.update(message);
        return sig.sign();
    }

    public ISignatureMechanismParams getSignatureMechanismParameters() {
        if (fullSignatureAlgorithmParamSpec instanceof PSSParameterSpec) {
            IBouncyCastleFactory factory = BouncyCastleFactoryCreator.getFactory();
            PSSParameterSpec pssSpec = (PSSParameterSpec) fullSignatureAlgorithmParamSpec;

            String oid = DigestAlgorithms.getAllowedDigest(digestAlgorithmName);
            IASN1ObjectIdentifier oidWrapper = factory.createASN1ObjectIdentifier(oid);

            return new RSASSAPSSMechanismParams(oidWrapper, pssSpec.getSaltLength(), pssSpec.getTrailerField());
        }
        return null;
    }
}
