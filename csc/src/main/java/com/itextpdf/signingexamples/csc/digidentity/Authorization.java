package com.itextpdf.signingexamples.csc.digidentity;

import java.io.IOException;
import java.lang.reflect.Field;

import com.google.gson.annotations.SerializedName;

import fi.methics.laverca.csc.CscClient;
import fi.methics.laverca.csc.json.CscErrorResp;
import fi.methics.laverca.csc.json.GsonMessage;
import okhttp3.Credentials;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * This class implements Authorization for Digidentity Signing via
 * their CSC API implementation. It employs their QR code based method
 * to not depend on the availability of callback routing.
 */
public class Authorization {
    //
    // Constructors
    //
    public Authorization() {
        this(new OkHttpClient());
    }

    public Authorization(OkHttpClient okHttpClient) {
        this.okHttpClient = okHttpClient;
    }

    //
    // Credentials
    //
    public Authorization withScope(String scope) {
        this.scope = scope;
        return this;
    }

    public Authorization withClient(String client) {
        this.client = client;
        return this;
    }

    public Authorization withSecret(String secret) {
        this.secret = secret;
        return this;
    }

    //
    // QR code URL retrieval
    //
    public String retrieveQrCodeUri() throws IOException {
        return retrieveQrCodeUri(OAUTH2_AUTHORIZE_URL);
    }

    public String retrieveQrCodeUri(String oAuth2AuthorizeUrl) throws IOException {
        Request request = new Request.Builder()
                .url(oAuth2AuthorizeUrl + "?client_id=" + client + "&scope=" + scope + "&response_type=code")
                .method("GET", null)
                .build();
        Response response = okHttpClient.newCall(request).execute();

        QrCodeUriResp qrCodeUriResp = QrCodeUriResp.fromResponse(response, QrCodeUriResp.class);

        if (qrCodeUriResp.data == null)
            throw new IOException("OAUTH2 AUTHORIZE Response: Missing or malformed data element");
        if (qrCodeUriResp.data.id == null)
            throw new IOException("OAUTH2 AUTHORIZE Response: Missing or malformed data.id element");
        if (!"passwordless_login_session".equals(qrCodeUriResp.data.type))
            throw new IOException("OAUTH2 AUTHORIZE Response: Missing or unexpected data.type element: " + qrCodeUriResp.data.type);
        if (qrCodeUriResp.data.attributes == null)
            throw new IOException("OAUTH2 AUTHORIZE Response: Missing or malformed data.attributes element");
        if (!"qr_code".equals(qrCodeUriResp.data.attributes.type))
            throw new IOException("OAUTH2 AUTHORIZE Response: Missing or unexpected data.attributes.type element: " + qrCodeUriResp.data.attributes.type);
        if (qrCodeUriResp.data.attributes.qr_code_uri == null)
            throw new IOException("OAUTH2 AUTHORIZE Response: Missing or malformed data.attributes.qr_code_uri element");

        authorizationCode = qrCodeUriResp.data.id;
        return qrCodeUriResp.data.attributes.qr_code_uri;
    }

    //
    // Polling for the Digidentity authorization token
    //
    public void pollAuthorization(long pollInterval) throws IOException {
        pollAuthorization(OAUTH2_TOKEN_URL, pollInterval);
    }

    public void pollAuthorization(String oauth2TokenUrl, long pollInterval) throws IOException {
        if (pollInterval < 0)
            pollInterval = 5000;

        for (;;) {
            try {
                Thread.sleep(pollInterval);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            RequestBody body = new MultipartBody.Builder().setType(MultipartBody.FORM)
                    .addFormDataPart("code", authorizationCode)
                    .addFormDataPart("grant_type", "authorization_code")
                    .build();
            Request request = new Request.Builder()
                    .url(oauth2TokenUrl)
                    .method("POST", body)
                    .addHeader("Authorization", Credentials.basic(client, secret))
                    .build();
            Response response = okHttpClient.newCall(request).execute();

            if (response.code() == 200) {
                TokenResp digidentityToken = TokenResp.fromResponse(response, TokenResp.class);
                accessToken = digidentityToken.access_token;
                refreshToken = digidentityToken.refresh_token;
                break;
            }
            if (response.code() == 400) {
                CscErrorResp errorResp = CscErrorResp.fromResponse(response);
                if ("session_not_found".equals(errorResp.error_description)) {
                    throw new IOException("OAUTH2 TOKEN Response: Session timeout OR non-existent session");
                }
                if (!"login_pending".equals(errorResp.error_description)) {
                    throw new IOException("OAUTH2 TOKEN Response: Unexpected error: " + errorResp.error_description);
                }
            } else {
                throw new IOException("OAUTH2 TOKEN Response: Unexpected response: " + response);
            }
        }
    }

    //
    // retrieve CSC token
    //
    public String retrieveCscToken() throws IOException {
        return retrieveCscToken(DIGIDENTITY_API_BASE_URL);
    }

    public String retrieveCscToken(String digidentityApiBaseUrl) throws IOException {
        RequestBody body = new MultipartBody.Builder().setType(MultipartBody.FORM)
                .addFormDataPart("access_token", accessToken)
                .build();
        Request request = new Request.Builder()
                .url(digidentityApiBaseUrl + "/api/esign/tokens")
                .method("POST", body)
                .build();
        Response response = okHttpClient.newCall(request).execute();

        TokenResp tokenResp = TokenResp.fromResponse(response, TokenResp.class);
        if (tokenResp.access_token == null)
            throw new IOException("API ESIGN TOKENS Response: Missing token");

        return tokenResp.access_token;
    }

    static void injectCscToken(CscClient cscClient, String accessToken) throws IllegalAccessException, NoSuchFieldException {
        Field accessTokenField = CscClient.class.getDeclaredField("access_token");
        accessTokenField.setAccessible(true);
        accessTokenField.set(cscClient, accessToken);
    }

    //
    // variables and constants
    //
    public final static String OAUTH2_AUTHORIZE_URL = "https://auth.digidentity-preproduction.eu/oauth2/authorize.json";
    public final static String OAUTH2_TOKEN_URL = "https://auth.digidentity-preproduction.eu/oauth2/token.json";
    public final static String DIGIDENTITY_API_BASE_URL = "https://esign.digidentity-preproduction.eu";
    public final static String CSC_API_BASE_URL = "https://esign.digidentity-preproduction.eu";

    final OkHttpClient okHttpClient;

    String scope;
    String client;
    String secret;

    String authorizationCode;
    String accessToken;
    String refreshToken;

    //
    // classes for wrapping JSON data objects
    //
    static class TokenResp extends GsonMessage {
        @SerializedName("access_token")
        public String access_token;

        @SerializedName("refresh_token")
        public String refresh_token;

        @SerializedName("scope")
        public String scope;
 
        @SerializedName("token_type")
        public String token_type;

        @SerializedName("expires_in")
        public int expires_in;
    }

    static class QrCodeUriResp extends GsonMessage {
        @SerializedName("data")
        public QrCodeUriRespData data;
    }

    static class QrCodeUriRespData extends GsonMessage {
        @SerializedName("id")
        public String id;

        @SerializedName("type")
        public String type;

        @SerializedName("attributes")
        public QrCodeUriRespDataAttributes attributes;
    }

    static class QrCodeUriRespDataAttributes extends GsonMessage {
        @SerializedName("type")
        public String type;

        @SerializedName("qr_code_uri")
        public String qr_code_uri;
    }
}
