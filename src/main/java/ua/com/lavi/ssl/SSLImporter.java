package ua.com.lavi.ssl;

import javax.net.ssl.*;
import java.io.*;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/**
 * Created by Oleksandr Loushkin on 2016-09-06.
 */
public class SSLImporter {

    private final static char[] HEXDIGITS = "0123456789abcdef".toCharArray();
    private final static String JSSECACERTS = "jssecacerts";
    private final static int SOCKET_TIMEOUT = 10000;
    private final static String DEFAULT_PASSPHRASE = "changeit";

    public static void main(String[] args) throws Exception {

        if (args.length == 0 || args.length > 2) {
            System.out.println("Usage: ssl-importer <host>:<port> [passPhrase]. Default passPhrase is: " + DEFAULT_PASSPHRASE);
            return;
        }

        String[] hostPort = args[0].split(":");
        String host = hostPort[0];
        int port = Integer.parseInt(hostPort[1]);
        String passPhrase = DEFAULT_PASSPHRASE;

        if (args.length == 2) {
            passPhrase = args[1];
        }

        System.out.println("Using passPhrase: " + passPhrase);

        //load existing certificate. http://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html
        File file = new File(JSSECACERTS);
        if (!file.isFile()) {
            char separatorChar = File.separatorChar;
            File dir = new File(System.getProperty("java.home") + separatorChar + "lib" + separatorChar + "security");
            file = new File(dir, JSSECACERTS);
            if (!file.isFile()) {
                file = new File(dir, "cacerts");
            }
        }
        System.out.println("Loading external KeyStore " + file + "...");
        InputStream in = new FileInputStream(file);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(in, passPhrase.toCharArray());
        in.close();

        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
        context.init(null, new TrustManager[]{tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        System.out.println("Opening connection to " + host + ":" + port + "...");
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(SOCKET_TIMEOUT);
        try {
            System.out.println("Starting SSL handshake...");
            socket.startHandshake();
            socket.close();
            System.out.println();
            System.out.println("No errors, certificate is already trusted");
        } catch (SSLException e) {
            System.out.println();
            e.printStackTrace(System.out);
        }

        X509Certificate[] chain = tm.getChain();
        if (chain == null) {
            System.out.println("Could not obtain server certificate chain");
            return;
        }

        System.out.println();
        System.out.println("Server sent " + chain.length + " certificate(s):");
        System.out.println();
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = chain[i];
            System.out.println(" " + (i + 1) + " Subject " + cert.getSubjectDN());
            System.out.println("   Issuer  " + cert.getIssuerDN());
            sha1.update(cert.getEncoded());
            System.out.println("   sha1    " + toHexString(sha1.digest()));
            md5.update(cert.getEncoded());
            System.out.println("   md5     " + toHexString(md5.digest()));
            System.out.println();
        }

        System.out.println("Enter number of certificate to add to trusted keystore or 'q' to quit: [1]");
        String line = new Scanner(System.in, Charset.defaultCharset().name()).nextLine().trim();
        int k;
        try {
            k = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;
        } catch (NumberFormatException e) {
            System.out.println("KeyStore not changed");
            return;
        }

        X509Certificate cert = chain[k];
        String alias = host + "-" + (k + 1);
        ks.setCertificateEntry(alias, cert);

        OutputStream out = new FileOutputStream(JSSECACERTS);
        ks.store(out, passPhrase.toCharArray());
        out.close();

        System.out.println();
        System.out.println(cert);
        System.out.println();
        System.out.printf("Added certificate to keystore 'jssecacerts' using alias '%s'%n", alias);
    }

    private static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes) {
            b &= 0xff;
            sb.append(HEXDIGITS[b >> 4]);
            sb.append(HEXDIGITS[b & 15]);
            sb.append(' ');
        }
        return sb.toString();
    }

}
