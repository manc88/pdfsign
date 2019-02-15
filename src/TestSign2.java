
/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 *
 * For more info, go to: http://itextpdf.com/learn
 */


import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

public class TestSign2 {

    public static final String KEYSTORE = "src/res/c.p12";
    public static final char[] PASSWORD = "pass123".toCharArray();
    public static final String SRC = "src/res/hello.pdf";
    public static final String DEST = "src/result/hello_signed%s.pdf";
    public static final String IMG = "src/res/1.gif";


    public void sign1(String src, String name, String dest,
                      Certificate[] chain, PrivateKey pk,
                      String digestAlgorithm, String provider, CryptoStandard subfilter,
                      String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(name);
        // Custom text and custom font
        appearance.setLayer2Text("This document was signed by Bruno Specimen");
        appearance.setLayer2Font(new Font(Font.FontFamily.TIMES_ROMAN));
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void sign2(String src, String name, String dest,
                      Certificate[] chain, PrivateKey pk,
                      String digestAlgorithm, String provider, CryptoStandard subfilter,
                      String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(name);
        // Custom text, custom font, and right-to-left writing
        appearance.setLayer2Text("\u0644\u0648\u0631\u0627\u0646\u0633 \u0627\u0644\u0639\u0631\u0628");
        appearance.setRunDirection(PdfWriter.RUN_DIRECTION_RTL);
        appearance.setLayer2Font(new Font(BaseFont.createFont("C:/windows/fonts/arialuni.ttf", BaseFont.IDENTITY_H, BaseFont.EMBEDDED), 12));
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void sign3(String src, String name, String dest,
                      Certificate[] chain, PrivateKey pk,
                      String digestAlgorithm, String provider, CryptoStandard subfilter,
                      String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(name);
        // Custom text and background image
        appearance.setLayer2Text("This document was signed by manc");
        appearance.setImage(Image.getInstance(IMG));
        appearance.setImageScale(1);
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void sign4(String src, String name, String dest,
                      Certificate[] chain, PrivateKey pk,
                      String digestAlgorithm, String provider, CryptoStandard subfilter,
                      String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(name);
        // Default text and scaled background image
        appearance.setImage(Image.getInstance(IMG));
        appearance.setImageScale(-1);
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, subfilter);
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException, DocumentException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        TestSign2 app = new TestSign2();
        app.sign1(SRC, "Signature1", String.format(DEST, 1), chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS,
                "Custom appearance example", "Ghent");
        app.sign2(SRC, "Signature1", String.format(DEST, 2), chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS,
                "Custom appearance example", "Ghent");
        app.sign3(SRC, "Signature1", String.format(DEST, 3), chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS,
                "Custom appearance example", "Ghent");
        app.sign4(SRC, "Signature1", String.format(DEST, 4), chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS,
                "Custom appearance example", "Ghent");
    }



}
