
# Cloud Signing Consortium (CSC) API Example - PDF Signing with iText

This repository provides an example of how to use the [Cloud Signature Consortium (CSC) API](https://cloudsignatureconsortium.org/) to sign PDF documents using the [iText](https://itextpdf.com/) library in Java. The example demonstrates how to implement digital signatures that comply with the EU’s eIDAS regulation and similar frameworks.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Setup](#setup)
    - [Step 1: Import Dependencies](#step-1-import-dependencies)
    - [Step 2: Create a CSC Client Instance](#step-2-create-a-csc-client-instance)
4. [Signing a PDF](#signing-a-pdf)
5. [Example Services](#example-services)
6. [Authorization Helper](#authorization-helper)

---

## Overview

This example demonstrates:

- Integrating the CSC API for remote signing.
- Using the iText library to sign PDF files.
- Supporting different CSC authentication mechanisms:
    - Username/password authentication.
    - OAuth2 for enhanced security.
- Managing CSC client operations using the Methics CSC client library.

The main focus is on **CSC API version 1**, as it remains widely used in production environments.

---

## Prerequisites

Before using this example, ensure you have the following:

- **Java 8** or higher.
- **Maven** for dependency management.
- **iText** library for PDF signing.
- **Methics CSC Client Library** for interacting with the CSC API.

Additionally, you need a valid CSC client account with access to one of the supported services:

- [Methics CSC Client Test Service](https://methics.fi) for username/password authentication.
- [Digidentity Pre-Production Environment](https://www.digidentity.eu) for OAuth2-based two-factor authentication.

---

## Setup

### Step 1: Import Dependencies

Add the required dependencies to your `pom.xml` file. You will need the Methics CSC client, iText, and related libraries such as Google Gson and OkHttp.

```xml
<dependencies>
    <dependency>
        <groupId>fi.methics</groupId>
        <artifactId>laverca-csc-client</artifactId>
        <version>1.2.0</version>
    </dependency>
</dependencies>
```

If the Methics CSC Client library is not available in public Maven repositories, you may need to build and install it locally.

---

### Step 2: Create a CSC Client Instance

Before signing a document, create and authenticate a `CscClient` instance. The authentication method depends on the service used.

#### Example: Username/Password Authentication

```java
CscClient client = new CscClient.Builder()
        .withBaseUrl("https://your-service-base-url")
        .withTrustInsecureConnections(true)
        .withUsername("your-username")
        .withPassword("your-password")
        .build();
client.authLogin();
```

For OAuth2-based services, refer to the [Authorization Helper](#authorization-helper) section.

---

## Signing a PDF

Once you have an authenticated `CscClient` instance, you can sign a PDF document using the `LavercaCscSignature` class.

#### Example:

```java
CscClient client = new CscClient.Builder()
        .withBaseUrl("https://your-service-base-url")
        .withTrustInsecureConnections(true)
        .withUsername("your-username")
        .withPassword("your-password")
        .build();
client.authLogin();

CscCredentialsListResp credentials = client.listCredentials();
LavercaCscSignature signature = new LavercaCscSignature(client, credentials.credentialIDs.get(0), "SHA256withRSA");

try (PdfReader pdfReader = new PdfReader("ToSign.pdf");
     OutputStream result = new FileOutputStream(new File("Signed.pdf"))) {
    PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());
    IExternalDigest externalDigest = new BouncyCastleDigest();
    pdfSigner.signDetached(externalDigest, signature, signature.getChain(), null, null, null, 0, CryptoStandard.CMS);
}
```

This code will sign the `ToSign.pdf` file and output the signed document as `Signed.pdf`.

---

## Example Services

### Methics CSC Client Test Service

Supports username/password authentication with SCAL1 assurance level. It is ideal for testing signing workflows in a simple environment.

### Digidentity Pre-Production Environment

Supports OAuth2-based authentication with a mobile app for two-factor authentication. It conforms to eIDAS regulations.

---

## Authorization Helper

If you are using Digidentity's OAuth2-based service, additional steps are needed for authentication and authorization.

#### Example: Retrieve QR Code URI

```java
Authorization authorization = new Authorization()
        .withScope(SCOPE)
        .withClient(CLIENT)
        .withSecret(SECRET);
String qrCodeUri = authorization.retrieveQrCodeUri();
Desktop.getDesktop().browse(new URI(qrCodeUri));
```

#### Poll for Authorization Token

```java
authorization.pollAuthorization(2000); // Poll every 2 seconds
```

#### Retrieve CSC Token

```java
String cscToken = authorization.retrieveCscToken();
```

#### Inject CSC Token into Client

```java
CscClient client = new CscClient.Builder()
        .withBaseUrl(Authorization.CSC_API_BASE_URL)
        .withTrustInsecureConnections(true)
        .build();
Authorization.injectCscToken(client, cscToken);
```

---
