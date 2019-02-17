
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.*;


public class PdfSingApp {

    private static String KEYSTORE;
    private static char[] PASSWORD;
    private static String SRC;
    private static String DEST;
    private static String TEMP;
    private static final String IMG = "src/res/logo.png";
    private static ExternalSignature pks;
    private static ExternalDigest digest;
    private static PrivateKey pk;
    private static Certificate[] chain;

    private final static Map<String, List<String>> params = new HashMap<>();

    private static void parseParams(String[] args){

        List<String> options = null;
        for (int i = 0; i < args.length; i++) {
            final String a = args[i];

            if (a.charAt(0) == '-') {
                if (a.length() < 2) {
                    System.err.println("Error at argument " + a);
                    return;
                }

                options = new ArrayList<>();
                params.put(a.substring(1).toUpperCase(), options);
            }
            else if (options != null) {
                options.add(a);
            }
            else {
                System.err.println("Illegal parameter usage");
                return;
            }
        }
    }

    private static void init() throws GeneralSecurityException, IOException{

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = ks.aliases().nextElement();
        pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        chain = ks.getCertificateChain(alias);
        pks = new PrivateKeySignature(pk, "SHA512", "BC");
        digest = new BouncyCastleDigest();

    }

    private static void sign() throws GeneralSecurityException, IOException, DocumentException {

        try (FileOutputStream os = new FileOutputStream(DEST)) {

            PdfReader reader = new PdfReader(SRC);
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();

            appearance.setReason("REASON");
            appearance.setLocation("LOCATION");
            appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);

            Image img = Image.getInstance(IMG);
            float w = img.getScaledWidth();
            float h = img.getScaledHeight();
            Rectangle rect = new Rectangle(36, 100 - h, 36 + w, 100);
            rect.setBorder(Rectangle.BOX);
            rect.setBorderWidth(2);

            appearance.setVisibleSignature(rect, 1, appearance.getFieldName());
            appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            appearance.setSignatureGraphic(Image.getInstance(IMG));

            MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, CryptoStandard.CMS);

        }

    }

    private static void signWithNoPRINT() throws GeneralSecurityException, IOException, DocumentException {

        try (   InputStream resource = new FileInputStream(SRC);
                OutputStream os = new FileOutputStream(TEMP)) {
            PdfReader reader = new PdfReader(resource);
            PdfStamper stamper = new PdfStamper(reader, os);
            PdfFormField field = PdfFormField.createSignature(stamper.getWriter());
            field.setFieldName("Signature");

            Image img = Image.getInstance(IMG);
            float w = img.getScaledWidth();
            float h = img.getScaledHeight();
            Rectangle rect = new Rectangle(36, 100 - h, 36 + w, 100);
            rect.setBorder(Rectangle.BOX);
            rect.setBorderWidth(2);

            field.setWidget(rect, PdfAnnotation.HIGHLIGHT_NONE);
            stamper.addAnnotation(field, 1);
            stamper.close();

        }

        try (InputStream resource = new FileInputStream(TEMP);
             OutputStream os = new FileOutputStream(DEST)) {
            PdfReader reader = new PdfReader(resource);
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');

            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setReason("reason");
            appearance.setLocation("location");
            appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
            appearance.setVisibleSignature("Signature");
            appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            appearance.setSignatureGraphic(Image.getInstance(IMG));
            MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, CryptoStandard.CMS);

        }

        try {
            Files.deleteIfExists(Paths.get(TEMP));
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) throws GeneralSecurityException, IOException, DocumentException {

        //-src D:\temp\hello.pdf -cert D:\temp\cert.p12 -pin pass123 -out D:\temp\res.pdf

        System.out.println("Parsing parameters...");
        parseParams(args);

        SRC = params.get("SRC").get(0);
        KEYSTORE = params.get("CERT").get(0);
        PASSWORD = params.get("PIN").get(0).toCharArray();
        DEST = params.get("OUT").get(0);
        TEMP = UUID.randomUUID().toString() + ".pdf";

        System.out.println("BouncyCastle initialization...");
        init();
        System.out.println("Signing...");
        signWithNoPRINT();

        System.out.println("Finished");

    }

}
