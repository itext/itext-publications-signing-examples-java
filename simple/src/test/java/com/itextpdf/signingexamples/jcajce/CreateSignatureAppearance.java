package com.itextpdf.signingexamples.jcajce;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfSignatureFormField;
import com.itextpdf.forms.fields.SignatureFormFieldBuilder;
import com.itextpdf.forms.fields.properties.SignedAppearanceText;
import com.itextpdf.forms.form.element.SignatureFieldAppearance;
import com.itextpdf.io.font.constants.StandardFonts;
import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.io.util.StreamUtil;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.geom.AffineTransform;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfArray;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.annot.PdfWidgetAnnotation;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.kernel.pdf.extgstate.PdfExtGState;
import com.itextpdf.kernel.pdf.xobject.PdfFormXObject;
import com.itextpdf.kernel.pdf.xobject.PdfImageXObject;
import com.itextpdf.layout.element.Div;
import com.itextpdf.layout.element.Image;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.properties.BackgroundImage;
import com.itextpdf.layout.properties.BackgroundSize;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;
import com.itextpdf.signatures.PrivateKeySignature;

/**
 * @author mkl
 */
class CreateSignatureAppearance {
    final static File RESULT_FOLDER = new File("target/test-outputs", "signature");

    final static String path = "keystore/johndoe.p12";
    final static char[] pass = "johndoe".toCharArray();
    static PrivateKey pk;
    static Certificate[] chain;

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        KeyStore ks = KeyStore.getInstance("pkcs12", "SunJSSE");
        ks.load(new FileInputStream(path), pass);
        String alias = "";
        Enumeration<String> aliases = ks.aliases();
        while (alias.equals("johndoe") == false && aliases.hasMoreElements()) {
            alias = aliases.nextElement();
        }
        pk = (PrivateKey) ks.getKey(alias, pass);
        chain = ks.getCertificateChain(alias);
    }

    @Test
    public void testModeDescription() throws IOException, GeneralSecurityException {
        try (   InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-DESCRIPTION.pdf")) ) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());

            pdfSigner.setPageRect(new Rectangle(100, 500, 300, 100));
            pdfSigner.setPageNumber(1);

            pdfSigner.setReason("Specimen");
            pdfSigner.setLocation("Boston");

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    public void testModeGraphic() throws IOException, GeneralSecurityException {
        try (   InputStream imageResource = getClass().getResourceAsStream("/iText badge.png");
                InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-GRAPHIC.pdf")) ) {
            ImageData data = ImageDataFactory.create(StreamUtil.inputStreamToArray(imageResource));

            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());

            pdfSigner.setPageRect(new Rectangle(100, 500, 300, 100));
            pdfSigner.setPageNumber(1);

            pdfSigner.setReason("Specimen");
            pdfSigner.setLocation("Boston");

            SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.getFieldName());
            appearance.setContent(data);
            pdfSigner.setSignatureAppearance(appearance);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    public void testModeGraphicAndDescription() throws IOException, GeneralSecurityException {
        try (   InputStream imageResource = getClass().getResourceAsStream("/johnDoe.png");
                InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-GRAPHIC_AND_DESCRIPTION.pdf")) ) {
            ImageData data = ImageDataFactory.create(StreamUtil.inputStreamToArray(imageResource));

            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());

            pdfSigner.setPageRect(new Rectangle(100, 500, 300, 100));
            pdfSigner.setPageNumber(1);

            pdfSigner.setReason("Specimen");
            pdfSigner.setLocation("Boston");

            SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.getFieldName());
            appearance.setContent(new SignedAppearanceText(), data); // SignedAppearanceText will be filled in automatically
            pdfSigner.setSignatureAppearance(appearance);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    public void testModeNameAndDescription() throws IOException, GeneralSecurityException {
        try (   InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-NAME_AND_DESCRIPTION.pdf")) ) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());

            pdfSigner.setPageRect(new Rectangle(100, 500, 300, 100));
            pdfSigner.setPageNumber(1);

            pdfSigner.setReason("Specimen");
            pdfSigner.setLocation("Boston");

            SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.getFieldName());
            appearance.setContent("", new SignedAppearanceText()); // "" and SignedAppearanceText will be filled in automatically
            pdfSigner.setSignatureAppearance(appearance);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    public void testReuseAppearance() throws IOException, GeneralSecurityException {
        File emptySignatureFile = createEmptySignatureField();

        try (   PdfReader pdfReader = new PdfReader(emptySignatureFile);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "emptySignatureField-signed.pdf")) ) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());
            pdfSigner.setFieldName("Signature");

            pdfSigner.setReason("Specimen");
            pdfSigner.setLocation("Boston");
            pdfSigner.getSignatureField().setReuseAppearance(true);

            SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.getFieldName());
            appearance.setContent("", new SignedAppearanceText()); // "" and SignedAppearanceText will be filled in automatically
            pdfSigner.setSignatureAppearance(appearance);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    File createEmptySignatureField() throws IOException {
        File emptySignatureFile = new File(RESULT_FOLDER, "emptySignatureField.pdf");
        try (   PdfDocument pdfDocument = new PdfDocument(new PdfWriter(emptySignatureFile))) {
            PdfSignatureFormField field = new SignatureFormFieldBuilder(pdfDocument, "Signature")
                    .setWidgetRectangle(new Rectangle(100, 600, 300, 100)).createSignature();
            createAppearance(field, pdfDocument);
            PdfAcroForm.getAcroForm(pdfDocument, true).addField(field, pdfDocument.addNewPage());
        }
        return emptySignatureFile;
    }

    void createAppearance(PdfSignatureFormField field, PdfDocument pdfDocument) throws IOException {
        PdfWidgetAnnotation widget = field.getWidgets().get(0);
        Rectangle rectangle = field.getWidgets().get(0).getRectangle().toRectangle();
        rectangle = new Rectangle(rectangle.getWidth(), rectangle.getHeight()); // necessary because of iText bug
        PdfFormXObject xObject = new PdfFormXObject(rectangle);
        xObject.makeIndirect(pdfDocument);
        PdfCanvas canvas = new PdfCanvas(xObject, pdfDocument);
        canvas.setExtGState(new PdfExtGState().setFillOpacity(.5f));
        try (   InputStream imageResource = getClass().getResourceAsStream("/Binary - Light Gray.png")    ) {
            ImageData data = ImageDataFactory.create(StreamUtil.inputStreamToArray(imageResource));
            canvas.addImageFittedIntoRectangle(data, rectangle, false);
        }
        widget.setNormalAppearance(xObject.getPdfObject());
    }

    @Test
    public void testSetImage() throws IOException, GeneralSecurityException {
        try (   InputStream imageResource = getClass().getResourceAsStream("/Binary - Orange.png");
                InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-setImage.pdf")) ) {
            ImageData data = ImageDataFactory.create(StreamUtil.inputStreamToArray(imageResource));
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());

            pdfSigner.setPageRect(new Rectangle(100, 500, 300, 100));
            pdfSigner.setPageNumber(1);

            pdfSigner.setReason("Specimen");
            pdfSigner.setLocation("Boston");

            SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.getFieldName());
            appearance.setContent("", new SignedAppearanceText()); // "" and SignedAppearanceText will be filled in automatically
            BackgroundSize size = new BackgroundSize();
            size.setBackgroundSizeToContain();
            appearance.setBackgroundImage(new BackgroundImage.Builder()
                    .setImage(new PdfImageXObject(data))
                    .setBackgroundSize(size)
                    .build());
            pdfSigner.setSignatureAppearance(appearance);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    public void testSetCaptions() throws IOException, GeneralSecurityException {
        try (   InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-setCaptions.pdf")) ) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());

            pdfSigner.setPageRect(new Rectangle(100, 500, 300, 100));
            pdfSigner.setPageNumber(1);
            pdfSigner.setReason("Specimen");
            pdfSigner.setLocation("Boston");

            SignedAppearanceText appearanceText = new SignedAppearanceText();
            appearanceText.setReasonLine("Objective: " + pdfSigner.getReason());
            appearanceText.setLocationLine("Whereabouts: " + pdfSigner.getLocation());
            SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.getFieldName());
            appearance.setContent(appearanceText);
            pdfSigner.setSignatureAppearance(appearance);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    public void testSetFontStyle() throws IOException, GeneralSecurityException {
        try (   InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-SetFontStyle.pdf")) ) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());

            pdfSigner.setPageRect(new Rectangle(100, 500, 300, 100));
            pdfSigner.setPageNumber(1);

            pdfSigner.setReason("Specimen");
            pdfSigner.setLocation("Boston");

            SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.getFieldName());
            appearance.setContent("", new SignedAppearanceText()); // "" and SignedAppearanceText will be filled in automatically
            appearance.setFont(PdfFontFactory.createFont(StandardFonts.COURIER));
            appearance.setFontColor(new DeviceRgb(0xF9, 0x9D, 0x25));
            appearance.setFontSize(10);
            pdfSigner.setSignatureAppearance(appearance);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    public void testSetDescriptionText() throws IOException, GeneralSecurityException {
        try (   InputStream imageResource = getClass().getResourceAsStream("/iText logo.png");
                InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-SetDescriptionText.pdf")) ) {
            ImageData data = ImageDataFactory.create(StreamUtil.inputStreamToArray(imageResource));

            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());

            pdfSigner.setPageRect(new Rectangle(100, 500, 300, 100));
            pdfSigner.setPageNumber(1);

            String restriction = "The qualified electronic signature at hand is restricted to present offers, invoices or credit notes to customers according to EU REGULATION No 910/2014 (23 July 2014) and German VAT law (§14 UStG).";
            pdfSigner.setReason(restriction);

            SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.getFieldName());
            appearance.setContent(restriction, data);
            pdfSigner.setSignatureAppearance(appearance);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    public void testCustomLayer0() throws IOException, GeneralSecurityException {
        try (   InputStream imageResource = getClass().getResourceAsStream("/johnDoe.png");
                InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-CustomLayer0.pdf")) ) {
            ImageData data = ImageDataFactory.create(StreamUtil.inputStreamToArray(imageResource));

            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());

            Rectangle rectangle = new Rectangle(100, 500, 300, 100);
            pdfSigner.setPageRect(rectangle);
            pdfSigner.setPageNumber(1);

            pdfSigner.setReason("Specimen");
            pdfSigner.setLocation("Boston");

            SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.getFieldName());
            appearance.setContent(new SignedAppearanceText(), data); // SignedAppearanceText will be filled in automatically
            pdfSigner.setSignatureAppearance(appearance);

            PdfFormXObject backgroundLayer = new PdfFormXObject(rectangle);
            PdfCanvas canvas = new PdfCanvas(backgroundLayer, pdfSigner.getDocument());
            canvas.setStrokeColor(new DeviceRgb(0xF9, 0x9D, 0x25)).setLineWidth(2);
            for (int i = (int)(rectangle.getLeft() - rectangle.getHeight()); i < rectangle.getRight(); i += 5)
                canvas.moveTo(i, rectangle.getBottom()).lineTo(i + rectangle.getHeight(), rectangle.getTop());
            canvas.stroke();
            pdfSigner.getSignatureField().setBackgroundLayer(backgroundLayer);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    public void testCustomLayer2() throws IOException, GeneralSecurityException {
        try (   InputStream badgeResource = getClass().getResourceAsStream("/iText badge.png");
                InputStream signResource = getClass().getResourceAsStream("/johnDoe.png");
                InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-CustomLayer2.pdf")) ) {
            ImageData badge = ImageDataFactory.create(StreamUtil.inputStreamToArray(badgeResource));
            ImageData sign = ImageDataFactory.create(StreamUtil.inputStreamToArray(signResource));

            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());

            Rectangle rectangle = new Rectangle(100, 500, 300, 100);
            pdfSigner.setPageRect(rectangle);
            pdfSigner.setPageNumber(1);

            PdfFormXObject foregroundLayer = new PdfFormXObject(rectangle);
            PdfCanvas canvas = new PdfCanvas(foregroundLayer, pdfSigner.getDocument());

            float xCenter = rectangle.getLeft() + rectangle.getWidth() / 2;
            float yCenter = rectangle.getBottom() + rectangle.getHeight() / 2;

            float badgeWidth = rectangle.getHeight() - 20;
            float badgeHeight = badgeWidth * badge.getHeight() / badge.getWidth();

            canvas.setLineWidth(20)
                  .setStrokeColorRgb(.9f, .1f, .1f)
                  .moveTo(rectangle.getLeft(), rectangle.getBottom())
                  .lineTo(rectangle.getRight(), rectangle.getTop())
                  .moveTo(xCenter + rectangle.getHeight(), yCenter - rectangle.getWidth())
                  .lineTo(xCenter - rectangle.getHeight(), yCenter + rectangle.getWidth())
                  .stroke();

            sign.setTransparency(new int[] {0, 0});
            canvas.addImageFittedIntoRectangle(sign, new Rectangle(0, yCenter, badgeWidth * sign.getWidth() / sign.getHeight() / 2, badgeWidth / 2), false);

            canvas.concatMatrix(AffineTransform.getRotateInstance(Math.atan2(rectangle.getHeight(), rectangle.getWidth()), xCenter, yCenter));
            canvas.addImageFittedIntoRectangle(badge, new Rectangle(xCenter - badgeWidth / 2, yCenter - badgeHeight + badgeWidth / 2, badgeWidth, badgeHeight), false);
            pdfSigner.getSignatureField().setSignatureAppearanceLayer(foregroundLayer);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    public void testCustomLayers() throws IOException, GeneralSecurityException {
        try (   InputStream badgeResource = getClass().getResourceAsStream("/iText badge.png");
                InputStream signResource = getClass().getResourceAsStream("/johnDoe.png");
                InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-CustomLayers.pdf")) ) {
            ImageData badge = ImageDataFactory.create(StreamUtil.inputStreamToArray(badgeResource));
            ImageData sign = ImageDataFactory.create(StreamUtil.inputStreamToArray(signResource));

            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());

            Rectangle rectangle = new Rectangle(100, 500, 300, 100);
            pdfSigner.setPageRect(rectangle);
            pdfSigner.setPageNumber(1);

            PdfFormXObject backgroundLayer = new PdfFormXObject(rectangle);
            PdfCanvas canvas = new PdfCanvas(backgroundLayer, pdfSigner.getDocument());
            canvas.setStrokeColor(new DeviceRgb(0xF9, 0x9D, 0x25)).setLineWidth(2);
            for (int i = (int)(rectangle.getLeft() - rectangle.getHeight()); i < rectangle.getRight(); i += 5)
                canvas.moveTo(i, rectangle.getBottom()).lineTo(i + rectangle.getHeight(), rectangle.getTop());
            canvas.stroke();

            PdfFormXObject foregroundLayer = new PdfFormXObject(rectangle);
            canvas = new PdfCanvas(foregroundLayer, pdfSigner.getDocument());

            float xCenter = rectangle.getLeft() + rectangle.getWidth() / 2;
            float yCenter = rectangle.getBottom() + rectangle.getHeight() / 2;

            float badgeWidth = rectangle.getHeight() - 20;
            float badgeHeight = badgeWidth * badge.getHeight() / badge.getWidth();

            canvas.setLineWidth(20)
                  .setStrokeColorRgb(.9f, .1f, .1f)
                  .moveTo(rectangle.getLeft(), rectangle.getBottom())
                  .lineTo(rectangle.getRight(), rectangle.getTop())
                  .moveTo(xCenter + rectangle.getHeight(), yCenter - rectangle.getWidth())
                  .lineTo(xCenter - rectangle.getHeight(), yCenter + rectangle.getWidth())
                  .stroke();

            sign.setTransparency(new int[] {0, 0});
            canvas.addImageFittedIntoRectangle(sign, new Rectangle(0, yCenter, badgeWidth * sign.getWidth() / sign.getHeight() / 2, badgeWidth / 2), false);

            canvas.concatMatrix(AffineTransform.getRotateInstance(Math.atan2(rectangle.getHeight(), rectangle.getWidth()), xCenter, yCenter));
            canvas.addImageFittedIntoRectangle(badge, new Rectangle(xCenter - badgeWidth / 2, yCenter - badgeHeight + badgeWidth / 2, badgeWidth, badgeHeight), false);

            pdfSigner.getSignatureField().setBackgroundLayer(backgroundLayer).setSignatureAppearanceLayer(foregroundLayer);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    public void testCustomLayer2OnReusedAppearance() throws IOException, GeneralSecurityException {
        File emptySignatureFile = createEmptySignatureField();

        try (   InputStream badgeResource = getClass().getResourceAsStream("/iText badge.png");
                InputStream signResource = getClass().getResourceAsStream("/johnDoe.png");
                PdfReader pdfReader = new PdfReader(emptySignatureFile);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-CustomLayer2OnReusedAppearance.pdf")) ) {
            ImageData badge = ImageDataFactory.create(StreamUtil.inputStreamToArray(badgeResource));
            ImageData sign = ImageDataFactory.create(StreamUtil.inputStreamToArray(signResource));

            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());
            pdfSigner.setFieldName("Signature");

            Rectangle rectangle = pdfSigner.getSignatureField().getFirstFormAnnotation().getWidget().getRectangle().toRectangle();

            PdfFormXObject foregroundLayer = new PdfFormXObject(rectangle);
            PdfCanvas canvas = new PdfCanvas(foregroundLayer, pdfSigner.getDocument());

            float xCenter = rectangle.getLeft() + rectangle.getWidth() / 2;
            float yCenter = rectangle.getBottom() + rectangle.getHeight() / 2;

            float badgeWidth = rectangle.getHeight() - 20;
            float badgeHeight = badgeWidth * badge.getHeight() / badge.getWidth();

            canvas.setLineWidth(20)
                  .setStrokeColorRgb(.9f, .1f, .1f)
                  .moveTo(rectangle.getLeft(), rectangle.getBottom())
                  .lineTo(rectangle.getRight(), rectangle.getTop())
                  .moveTo(xCenter + rectangle.getHeight(), yCenter - rectangle.getWidth())
                  .lineTo(xCenter - rectangle.getHeight(), yCenter + rectangle.getWidth())
                  .stroke();

            sign.setTransparency(new int[] {0, 0});
            canvas.addImageFittedIntoRectangle(sign, new Rectangle(0, yCenter, badgeWidth * sign.getWidth() / sign.getHeight() / 2, badgeWidth / 2), false);

            canvas.concatMatrix(AffineTransform.getRotateInstance(Math.atan2(rectangle.getHeight(), rectangle.getWidth()), xCenter, yCenter));
            canvas.addImageFittedIntoRectangle(badge, new Rectangle(xCenter - badgeWidth / 2, yCenter - badgeHeight + badgeWidth / 2, badgeWidth, badgeHeight), false);

            pdfSigner.getSignatureField().setReuseAppearance(true).setSignatureAppearanceLayer(foregroundLayer);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    public void testMachineReadables() throws IOException, GeneralSecurityException {
        try (   InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-MachineReadables.pdf")) ) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());

            pdfSigner.setContact("Test content of Contact field");
            pdfSigner.setReason("Test content of Reason field");
            pdfSigner.setLocation("Test content of Location field");
            pdfSigner.setSignatureCreator("Test content of Signature Creator field");

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    /**
     * This test illustrates an issue in the
     * {@link com.itextpdf.forms.fields.PdfSignatureFormField#setReuseAppearance(boolean) ReuseAppearance}
     * feature of iText: Here the complete normal appearance of the unsigned field is re-used as n0 layer of the signed
     * field. Unfortunately it was forgotten that the original appearance was displayed so that its BBox transformed by
     * its matrix fits into the annotation rectangle. If BBox of the original appearance does not have its lower left
     * corner in the origin or its matrix is not the identity, therefore, the re-used appearance usually is displayed in
     * differently if at all.
     */
    @Test
    public void testReuseSpecialAppearance() throws IOException, GeneralSecurityException {
        File emptySignatureFile = createSpecialEmptySignatureField();

        try (   PdfReader pdfReader = new PdfReader(emptySignatureFile);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "specialEmptySignatureField-signed.pdf")) ) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());
            pdfSigner.setFieldName("Signature");

            pdfSigner.setReason("Specimen");
            pdfSigner.setLocation("Boston");

            pdfSigner.getSignatureField().setReuseAppearance(true);

            SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.getFieldName());
            appearance.setContent("", new SignedAppearanceText()); // "" and SignedAppearanceText will be filled in automatically
            appearance.setFontColor(ColorConstants.LIGHT_GRAY);
            pdfSigner.setSignatureAppearance(appearance);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    File createSpecialEmptySignatureField() throws IOException {
        File emptySignatureFile = new File(RESULT_FOLDER, "specialEmptySignatureField.pdf");
        try (   PdfDocument pdfDocument = new PdfDocument(new PdfWriter(emptySignatureFile))) {
            PdfSignatureFormField field = new SignatureFormFieldBuilder(pdfDocument, "Signature")
                    .setWidgetRectangle(new Rectangle(100, 600, 300, 100)).createSignature();
            createSpecialAppearance(field, pdfDocument);
            PdfAcroForm.getAcroForm(pdfDocument, true).addField(field, pdfDocument.addNewPage());
        }
        return emptySignatureFile;
    }

    void createSpecialAppearance(PdfSignatureFormField field, PdfDocument pdfDocument) throws IOException {
        PdfWidgetAnnotation widget = field.getWidgets().get(0);
        Rectangle rectangle = field.getWidgets().get(0).getRectangle().toRectangle();
        rectangle = new Rectangle(-rectangle.getWidth()/4, -rectangle.getHeight()/4, rectangle.getWidth(), rectangle.getHeight());
        PdfFormXObject xObject = new PdfFormXObject(rectangle);
        xObject.makeIndirect(pdfDocument);
        float[] matrix = new float[6];
        AffineTransform.getRotateInstance(Math.PI / 4).getMatrix(matrix);
        xObject.getPdfObject().put(PdfName.Matrix, new PdfArray(matrix));
        PdfCanvas canvas = new PdfCanvas(xObject, pdfDocument);
        try (   InputStream imageResource = getClass().getResourceAsStream("/Binary - Light Gray.png")    ) {
            ImageData data = ImageDataFactory.create(StreamUtil.inputStreamToArray(imageResource));
            canvas.addImageFittedIntoRectangle(data, rectangle, false);
        }
        canvas.setFillColorGray(0);
        canvas.setFontAndSize(PdfFontFactory.createFont(), rectangle.getHeight()/2);
        canvas.beginText();
        canvas.showText("Test");
        canvas.endText();
        widget.setNormalAppearance(xObject.getPdfObject());
    }

    @Test
    public void testSignInNewHierarchicalField() throws IOException, GeneralSecurityException {
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
        try (   InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-SignInNewHierarchicalField.pdf")) ) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());
            pdfSigner.setFieldName("Form.Subform.Signature");

            pdfSigner.setPageRect(new Rectangle(100, 500, 300, 100));
            pdfSigner.setPageNumber(1);

            pdfSigner.setReason("Hierarchical Signature Field");
            pdfSigner.setLocation("Boston");

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }});
    }

    @Test
    public void testCustomAppearance() throws IOException, GeneralSecurityException {
        try (   InputStream badgeResource = getClass().getResourceAsStream("/iText badge.png");
                InputStream signResource = getClass().getResourceAsStream("/johnDoe.png");
                InputStream resource = getClass().getResourceAsStream("/Blank.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "test-CustomAppearance.pdf")) ) {
            ImageData badge = ImageDataFactory.create(StreamUtil.inputStreamToArray(badgeResource));
            ImageData sign = ImageDataFactory.create(StreamUtil.inputStreamToArray(signResource));

            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties());

            Rectangle rectangle = new Rectangle(100, 500, 300, 100);
            pdfSigner.setPageRect(rectangle);
            pdfSigner.setPageNumber(1);

            Paragraph paragraph = new Paragraph();

            Image signImage = new Image(sign);
            signImage.setAutoScale(true);
            paragraph.add(signImage);
            Image badgeImage = new Image(badge);
            badgeImage.setRotationAngle(- Math.PI / 16);
            badgeImage.setAutoScale(true);
            paragraph.add(badgeImage);

            Div div = new Div();
            div.add(paragraph);

            SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.getFieldName());
            appearance.setContent(div);
            pdfSigner.setSignatureAppearance(appearance);

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }
}
