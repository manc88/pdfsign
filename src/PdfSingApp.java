
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
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;


public class PdfSingApp {

    private static final int padding = 20;
    private static String KEYSTORE;
    private static char[] PASSWORD;
    private static char[] DEFAULTPASSWORD = "pass123".toCharArray();
    private static String SRC;
    private static String DEST;
    private static String TEMP;
    private static String IMG;
    private static ExternalSignature pks;
    private static ExternalDigest digest;
    private static PrivateKey pk;
    private static Certificate[] chain;
    private static String IMAGEPOS = "LD";
    private static boolean paramsInitialized = true;
    private static boolean useDefaultKeystore = false;
    private static boolean useDefaultImage = false;
    private static boolean cryptoInitialized = true;

    private final static Map<String, List<String>> params = new HashMap<>();


    public static void main(String[] args) throws GeneralSecurityException, IOException, DocumentException {

        //-src D:\temp\hello.pdf -cert D:\temp\cert.p12 -pin pass123 -out D:\temp\res.pdf -img logo.png -imgpos RU

        System.out.println("Parsing parameters...");
        parseParams(args);

        System.out.println("Initializing parameters...");
        initParams();

        if(!paramsInitialized){
            return;
        }

        System.out.println("BouncyCastle initialization...");
        init();

        if(!cryptoInitialized){
            return;
        }

        System.out.println("Signing...");
        signWithNoPRINT();
        System.out.println("Finished");

    }

    private static void signWithNoPRINT() throws GeneralSecurityException, IOException, DocumentException {

        Image img;
        if(useDefaultImage){
            //img = Image.getInstance(PdfSingApp.class.getClassLoader().getResource("l.png").getPath());
            InputStream imgStream = PdfSingApp.class.getResourceAsStream("l.png");
            byte[] targetArray = new byte[imgStream.available()];
            imgStream.read(targetArray);
            img = Image.getInstance(targetArray);
        }else{
            img = Image.getInstance(IMG);
        }

        try (   InputStream resource = new FileInputStream(SRC);
                OutputStream os = new FileOutputStream(TEMP)) {
            PdfReader reader = new PdfReader(resource);
            PdfStamper stamper = new PdfStamper(reader, os);
            PdfFormField field = PdfFormField.createSignature(stamper.getWriter());
            field.setFieldName("SignaturePIK");

            float w = img.getScaledWidth();
            float h = img.getScaledHeight();

            Rectangle ps = reader.getPageSizeWithRotation(1);
            Rectangle rect = getImgRectangle(ps,h,w);
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
            appearance.setVisibleSignature("SignaturePIK");
            appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            appearance.setSignatureGraphic(img);
            MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, CryptoStandard.CMS);

        }

        try {
            Files.deleteIfExists(Paths.get(TEMP));
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private static void initParams() {

        //SRC
        if (params.get("SRC")==null){
            System.out.println("SRC parameter not found");
            paramsInitialized = false;
            return;
        }else{
            SRC = params.get("SRC").get(0);
        }

        if (params.get("IMGPOS")!=null){
            IMAGEPOS = params.get("IMGPOS").get(0);
        }

        //CERT
        if (params.get("CERT")==null){
            System.out.println("Using default KEYSTORE");
            useDefaultKeystore = true;
        }else{
            KEYSTORE = params.get("CERT").get(0);
        }

        //PIN
        if (useDefaultKeystore && params.get("PIN")==null){
            System.out.println("Using default KEYSTORE PIN");
            PASSWORD = DEFAULTPASSWORD;
        }else if(!useDefaultKeystore && params.get("PIN")==null){
            System.out.println("PIN not found");
            paramsInitialized = false;
            return;
        }else{
            PASSWORD = params.get("PIN").get(0).toCharArray();
        }

        //OUT
        if (params.get("OUT")==null){
            // expression will remove the last dot followed by one or more characters.
            DEST = SRC.replaceFirst("[.][^.]+$", "") + "_signed.pdf";
            System.out.println("Using default OUT name: " + DEST);
        }else{
            DEST = params.get("OUT").get(0);
        }

        //IMG
        if (params.get("IMG")==null){
            System.out.println("Using default IMG");
            useDefaultImage = true;
        }else{
            IMG = params.get("IMG").get(0);
        }

        //TEMP
        TEMP = UUID.randomUUID().toString() + ".pdf";

    }

    private static Rectangle getImgRectangle(Rectangle ps,float imgH,float imgW){

        switch (IMAGEPOS.toUpperCase()) {
            case "LD":
                return new Rectangle(padding, padding, padding + imgW, padding+imgH);
            case "LU":
                return new Rectangle(padding, ps.getHeight()-imgH-padding, padding + imgW, ps.getHeight()-padding);
            case "RU":
                return new Rectangle(ps.getWidth()-padding-imgW, ps.getHeight()-imgH-padding, ps.getWidth()-padding, ps.getHeight()-padding);
            case "RD":
                return new Rectangle(ps.getWidth()-padding-imgW, padding, ps.getWidth()-padding, padding+imgH);
            default:
                return new Rectangle(padding, padding, padding + imgW, padding+imgH);
        }



    }

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

    private static void init(){

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        KeyStore ks;

        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            e.printStackTrace();
            cryptoInitialized = false;
            return;
        }

        InputStream stream;

        if(useDefaultKeystore){
            //stream = new FileInputStream(PdfSingApp.class.getResource("s.p12").getPath());
            stream = PdfSingApp.class.getResourceAsStream("s.p12");
            if (stream == null){
                System.out.println("No default keystore found");
                cryptoInitialized = false;
                return;
            }
        }else{
            try {
                stream = new FileInputStream(KEYSTORE);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                cryptoInitialized = false;
                return;
            }
        }

        try {
            ks.load(stream, PASSWORD);
            String alias = ks.aliases().nextElement();
            pk = (PrivateKey) ks.getKey(alias, PASSWORD);
            chain = ks.getCertificateChain(alias);
            pks = new PrivateKeySignature(pk, "SHA512", "BC");
            digest = new BouncyCastleDigest();
        } catch (Exception e) {
            e.printStackTrace();
            cryptoInitialized = false;
        }

    }


}
