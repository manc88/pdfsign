//https://stackoverflow.com/questions/24911238/programmatically-import-cer-certificate-into-keystore

import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;


public class KS {

    private static ExternalSignature pks;
    private static ExternalDigest digest;
    private static PrivateKey pk;
    private static Certificate[] chain;
    private static char[] PASSWORD = "pass123".toCharArray();

    public static void main(String[] args) throws Exception{

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        KeyStore ks;
        InputStream stream;

        stream = PdfSingApp.class.getResourceAsStream("s.cer");

        ks = KeyStore.getInstance("JCEKS");
        ks.load(stream, null);
        X509Certificate clientCertificate = createX509CertificateFromFile(stream);


        ks.setCertificateEntry("certificate", clientCertificate);

        String alias = ks.aliases().nextElement();
        pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        //Certificate cert=ks.getCertificate(alias);
        //PublicKey publicKey= cert.getPublicKey();
        pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        //Key key=ks.getKey(alias,PASSWORD);
        //KeyPair kp= new KeyPair(publicKey,(PrivateKey) key);

        chain = ks.getCertificateChain(alias);
        pks = new PrivateKeySignature(pk, "SHA512", "BC");
        digest = new BouncyCastleDigest();

    }


    private byte[]  getB(InputStream in)
            throws IOException {

        byte[] buff = new byte[8000];

        int bytesRead = 0;

        ByteArrayOutputStream bao = new ByteArrayOutputStream();

        while((bytesRead = in.read(buff)) != -1) {
            bao.write(buff, 0, bytesRead);
        }

        return bao.toByteArray();

    }


















    private static X509Certificate createX509CertificateFromFile(final InputStream inputStream) throws IOException, CertificateException
    {
        // Load an X509 certificate from the specified certificate file name


        final CertificateFactory certificateFactoryX509 = CertificateFactory.getInstance("X.509");
        final X509Certificate certificate = (X509Certificate) certificateFactoryX509.generateCertificate(inputStream);
        inputStream.close();

        return certificate;
    }

}
