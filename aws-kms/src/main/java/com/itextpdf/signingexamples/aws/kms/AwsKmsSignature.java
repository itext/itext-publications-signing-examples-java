package com.itextpdf.signingexamples.aws.kms;

import java.security.GeneralSecurityException;
import java.util.List;
import java.util.function.Function;

import com.itextpdf.signatures.IExternalSignature;

import com.itextpdf.signatures.ISignatureMechanismParams;
import com.itextpdf.signatures.RSASSAPSSMechanismParams;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * @author mkl
 */
public class AwsKmsSignature implements IExternalSignature {
    public AwsKmsSignature(String keyId) {
        this(keyId, a -> a != null && a.size() > 0 ? a.get(0) : null);
    }

    public AwsKmsSignature(String keyId, Function<List<SigningAlgorithmSpec>, SigningAlgorithmSpec> selector) {
        this.keyId = keyId;

        try (   KmsClient kmsClient = KmsClient.create() ) {
            GetPublicKeyRequest getPublicKeyRequest = GetPublicKeyRequest.builder()
                    .keyId(keyId)
                    .build();
            GetPublicKeyResponse getPublicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest);
            signingAlgorithmSpec = selector.apply(getPublicKeyResponse.signingAlgorithms());
            switch(signingAlgorithmSpec) {
            case ECDSA_SHA_256:
            case ECDSA_SHA_384:
            case ECDSA_SHA_512:
            case RSASSA_PKCS1_V1_5_SHA_256:
            case RSASSA_PKCS1_V1_5_SHA_384:
            case RSASSA_PKCS1_V1_5_SHA_512:
            case RSASSA_PSS_SHA_256:
            case RSASSA_PSS_SHA_384:
            case RSASSA_PSS_SHA_512:
                break;
            default:
                throw new IllegalArgumentException(String.format("Unknown signing algorithm: %s", signingAlgorithmSpec));
            }
        }
    }

    @Override
    public String getDigestAlgorithmName() {
        switch(signingAlgorithmSpec) {
        case ECDSA_SHA_256:
        case RSASSA_PKCS1_V1_5_SHA_256:
        case RSASSA_PSS_SHA_256:
            return "SHA-256";
        case ECDSA_SHA_384:
        case RSASSA_PKCS1_V1_5_SHA_384:
        case RSASSA_PSS_SHA_384:
            return "SHA-384";
        case ECDSA_SHA_512:
        case RSASSA_PKCS1_V1_5_SHA_512:
        case RSASSA_PSS_SHA_512:
            return "SHA-512";
        default:
            return null;
        }
    }

    @Override
    public String getSignatureAlgorithmName() {
        switch(signingAlgorithmSpec) {
        case ECDSA_SHA_256:
        case ECDSA_SHA_384:
        case ECDSA_SHA_512:
            return "ECDSA";
        case RSASSA_PKCS1_V1_5_SHA_256:
        case RSASSA_PKCS1_V1_5_SHA_384:
        case RSASSA_PKCS1_V1_5_SHA_512:
            return "RSA";
        case RSASSA_PSS_SHA_256:
        case RSASSA_PSS_SHA_384:
        case RSASSA_PSS_SHA_512:
            return "RSASSA-PSS";
        default:
            return null;
        }
    }

    @Override
    public ISignatureMechanismParams getSignatureMechanismParameters() {
        switch (signingAlgorithmSpec)
        {
            case RSASSA_PSS_SHA_256:
                return RSASSAPSSMechanismParams.createForDigestAlgorithm("SHA-256");
            case RSASSA_PSS_SHA_384:
                return RSASSAPSSMechanismParams.createForDigestAlgorithm("SHA-384");
            case RSASSA_PSS_SHA_512:
                return RSASSAPSSMechanismParams.createForDigestAlgorithm("SHA-512");
            case ECDSA_SHA_256:
            case ECDSA_SHA_384:
            case ECDSA_SHA_512:
            case RSASSA_PKCS1_V1_5_SHA_256:
            case RSASSA_PKCS1_V1_5_SHA_384:
            case RSASSA_PKCS1_V1_5_SHA_512:
            default:
                return null;
        }
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        try (   KmsClient kmsClient = KmsClient.create() ) {
            SignRequest signRequest = SignRequest.builder()
                    .signingAlgorithm(signingAlgorithmSpec)
                    .keyId(keyId)
                    .messageType(MessageType.RAW)
                    .message(SdkBytes.fromByteArray(message))
                    .build();
            SignResponse signResponse = kmsClient.sign(signRequest);
            return signResponse.signature().asByteArray();
        }
    }

    final String keyId;
    final SigningAlgorithmSpec signingAlgorithmSpec;
}
