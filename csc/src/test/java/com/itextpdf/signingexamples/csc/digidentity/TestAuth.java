package com.itextpdf.signingexamples.csc.digidentity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.lang.reflect.Field;

import org.junit.jupiter.api.Test;

import com.google.gson.annotations.SerializedName;

import fi.methics.laverca.csc.CscClient;
import fi.methics.laverca.csc.json.GsonMessage;
import fi.methics.laverca.csc.json.credentials.CscCredentialsListResp;
import okhttp3.Credentials;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * @author mkl
 */
public class TestAuth {
    // SET CREDENTIALS HERE FOR TESTING.
    public final static String CLIENT = "CLIENT_NAME";
    public final static String SECRET = "CLIENT_SECRET";
    public final static String SCOPE = "CLIENT_SCOPE";

    public final static String API_BASE_URL = "https://esign.digidentity-preproduction.eu";
    public final static String CSC_BASE_URL = "https://esign.digidentity-preproduction.eu";
    public final static String OAUTH_AUTHORIZE_URL = "https://auth.digidentity-preproduction.eu/oauth2/authorize.json";
    public final static String OAUTH_TOKEN_URL = "https://auth.digidentity-preproduction.eu/oauth2/token.json";

    @Test
    public void testRetrieveClientApplicationToken() throws IOException {
        OkHttpClient client = new OkHttpClient();

        System.out.println();
        System.out.println("Retrieve client application token. Attempt to retrieve CSC credentials. Will Fail.");
        System.out.println();

        RequestBody body = new MultipartBody.Builder().setType(MultipartBody.FORM)
          .addFormDataPart("grant_type", "client_credentials")
          .addFormDataPart("scope", SCOPE)
          .build();
        Request request = new Request.Builder()
          .url(OAUTH_TOKEN_URL)
          .method("POST", body)
          .addHeader("Authorization", Credentials.basic(CLIENT, SECRET))
          .build();
        Response response = client.newCall(request).execute();
        System.out.println(response.toString());
        assertEquals(200, response.code());

        TokenResp tokenResp = TokenResp.fromResponse(response, TokenResp.class);
        System.out.println(tokenResp);

        body = new MultipartBody.Builder().setType(MultipartBody.FORM)
          .addFormDataPart("access_token", tokenResp.access_token)
          .build();
        request = new Request.Builder()
          .url(API_BASE_URL + "/api/esign/tokens")
          .method("POST", body)
          .build();
        response = client.newCall(request).execute();
        System.out.println(response.toString());
        assertEquals(201, response.code());

        tokenResp = TokenResp.fromResponse(response, TokenResp.class);
        System.out.println(tokenResp);

        MediaType JSON = MediaType.parse("application/json; charset=utf-8");
        body = RequestBody.create("{}", JSON);
        request = new Request.Builder()
          .url(CSC_BASE_URL + "/csc/v1/credentials/list")
          .method("POST", body)
          .addHeader("Authorization", "Bearer " + tokenResp.access_token)
          .build();
        response = client.newCall(request).execute();
        System.out.println(response.toString());
        assertEquals(401, response.code());

        System.out.println(response.body().string());
    }

    @Test
    public void testRetrieveUserApplicationTokenQr() throws IOException, NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, InterruptedException {
        OkHttpClient client = new OkHttpClient();
        RequestBody body = null;

        System.out.println();
        System.out.println("Retrieve user application token. Attempt to retrieve CSC credentials. Should succeed.");
        System.out.println();

        Request request = new Request.Builder()
            .url(OAUTH_AUTHORIZE_URL + "?client_id=" + CLIENT + "&scope=" + SCOPE + "&response_type=code")
            .method("GET", null)
            .build();
        Response response = client.newCall(request).execute();
        System.out.println(response.toString());
        assertEquals(200, response.code());

        QrCodeUriResp qrCodeUriResp = GsonMessage.fromResponse(response, QrCodeUriResp.class);
        System.out.println(qrCodeUriResp);
        assertNotNull(qrCodeUriResp);
        assertNotNull(qrCodeUriResp.data);
        assertNotNull(qrCodeUriResp.data.id);
        assertEquals("passwordless_login_session", qrCodeUriResp.data.type);
        assertNotNull(qrCodeUriResp.data.attributes);
        assertEquals("qr_code", qrCodeUriResp.data.attributes.type);
        assertNotNull(qrCodeUriResp.data.attributes.qr_code_uri);

        TokenResp digidentityToken = null;

        while (digidentityToken == null) {
            System.out.println();
            System.out.println("Please authorize at " + qrCodeUriResp.data.attributes.qr_code_uri);
            System.out.println();

            Thread.sleep(5000);

            body = new MultipartBody.Builder().setType(MultipartBody.FORM)
                    .addFormDataPart("code", qrCodeUriResp.data.id)
                    .addFormDataPart("grant_type", "authorization_code")
                    .build();
            request = new Request.Builder()
                    .url(OAUTH_TOKEN_URL)
                    .method("POST", body)
                    .addHeader("Authorization", Credentials.basic(CLIENT, SECRET))
                    .build();
            response = client.newCall(request).execute();
            System.out.println(response.toString());

            if (response.code() == 200) {
                digidentityToken = TokenResp.fromResponse(response, TokenResp.class);
                System.out.println(digidentityToken);
            } else {
                assertEquals(400, response.code());
                ErrorResp errorResp = ErrorResp.fromJson(response.body().string(), ErrorResp.class);
                System.out.println(errorResp);
                assertEquals("login_pending", errorResp.error_description);
            }
        }

        body = new MultipartBody.Builder().setType(MultipartBody.FORM)
                .addFormDataPart("access_token", digidentityToken.access_token)
                .build();
        request = new Request.Builder()
                .url(API_BASE_URL + "/api/esign/tokens")
                .method("POST", body)
                .build();
        response = client.newCall(request).execute();
        System.out.println(response.toString());
        assertEquals(201, response.code());

        TokenResp tokenResp = TokenResp.fromResponse(response, TokenResp.class);
        System.out.println(tokenResp);

        MediaType JSON = MediaType.parse("application/json; charset=utf-8");
        body = RequestBody.create("{}", JSON);
        request = new Request.Builder()
                .url(CSC_BASE_URL + "/csc/v1/credentials/list")
                .method("POST", body)
                .addHeader("Authorization", "Bearer " + tokenResp.access_token)
                .build();
        response = client.newCall(request).execute();
        System.out.println(response.toString());
        System.out.println(response.body().string());

        //*
        CscClient cscClient = new CscClient.Builder().withBaseUrl("https://esign.digidentity-preproduction.eu")
                .withTrustInsecureConnections(true)
                .withUsername("")
                .withPassword("")
                .build();
        //cscClient.authLogin();
        Field accessTokenField = CscClient.class.getDeclaredField("access_token");
        accessTokenField.setAccessible(true);
        accessTokenField.set(cscClient, tokenResp.access_token);
        CscCredentialsListResp credentials = cscClient.listCredentials();
        System.out.println(credentials);
        //*/
    }

    static class ErrorResp extends GsonMessage {
        @SerializedName("error")
        public String error;

        @SerializedName("error_description")
        public String error_description;
    }

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
