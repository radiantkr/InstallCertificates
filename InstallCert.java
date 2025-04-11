import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Updated for Java 17.
 * Usage:
 *   java InstallCert [--proxy=host:port] host[:port] [passphrase] [--quiet]
 */
public class InstallCertUpdated {

    public static void main(String[] args) throws Exception {
        String host = null;
        int port = 443;
        char[] passphrase = "changeit".toCharArray();
        boolean useProxy = false, isQuiet = false, invalidArgs = false;

        String proxyHost = null;
        int proxyPort = -1;
        Socket underlying = null;

        for (int i = 0; i < args.length; i++) {
            var arg = args[i];
            if (arg.startsWith("--proxy=")) {
                useProxy = true;
                var proxy = arg.substring("--proxy=".length());
                var parts = proxy.split(":");
                proxyHost = parts[0];
                proxyPort = Integer.parseInt(parts[1]);
            } else if (arg.equals("--quiet")) {
                isQuiet = true;
            } else if (host == null) {
                var parts = arg.split(":");
                host = parts[0];
                if (parts.length > 1) port = Integer.parseInt(parts[1]);
            } else if (passphrase == null) {
                passphrase = arg.toCharArray();
            } else {
                invalidArgs = true;
            }
        }

        if (host == null || invalidArgs) {
            System.out.println("""
                Usage:
                  java InstallCert [--proxy=host:port] host[:port] [passphrase] [--quiet]
                """);
            return;
        }

        // Load keystore
        var file = new File("jssecacerts");
        if (!file.isFile()) {
            var sep = File.separator;
            var dir = new File(System.getProperty("java.home") + sep + "lib" + sep + "security");
            file = new File(dir, "jssecacerts");
            if (!file.isFile()) file = new File(dir, "cacerts");
        }

        System.out.println("Loading KeyStore " + file + "...");
        KeyStore ks;
        try (InputStream in = new FileInputStream(file)) {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(in, passphrase);
        }

        if (useProxy) {
            var proxyAddr = new InetSocketAddress(proxyHost, proxyPort);
            underlying = new Socket(new Proxy(Proxy.Type.HTTP, proxyAddr));
        }

        var context = SSLContext.getInstance("TLS");
        var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        var defaultTm = (X509TrustManager) tmf.getTrustManagers()[0];
        var savingTm = new SavingTrustManager(defaultTm);
        context.init(null, new TrustManager[]{savingTm}, null);

        var factory = context.getSocketFactory();
        System.out.printf("Opening connection to %s:%d%s...%n", host, port,
                useProxy ? " via proxy " + proxyHost + ":" + proxyPort : "");

        SSLSocket socket;
        if (useProxy) {
            underlying.connect(new InetSocketAddress(host, port));
            socket = (SSLSocket) factory.createSocket(underlying, host, port, true);
        } else {
            socket = (SSLSocket) factory.createSocket(host, port);
        }
        socket.setSoTimeout(10_000);

        try {
            System.out.println("Starting SSL handshake...");
            socket.startHandshake();
            socket.close();
            System.out.println("\nNo errors, certificate is already trusted");
        } catch (SSLException e) {
            System.out.println();
            e.printStackTrace(System.out);
        }

        var chain = savingTm.chain;
        if (chain == null) {
            System.out.println("Could not obtain server certificate chain");
            return;
        }

        System.out.printf("%nServer sent %d certificate(s):%n%n", chain.length);
        var sha1 = MessageDigest.getInstance("SHA1");
        var md5 = MessageDigest.getInstance("MD5");

        for (int i = 0; i < chain.length; i++) {
            var cert = chain[i];
            System.out.printf(" %d Subject: %s%n", i + 1, cert.getSubjectDN());
            System.out.printf("   Issuer:  %s%n", cert.getIssuerDN());
            sha1.update(cert.getEncoded());
            System.out.printf("   sha1:    %s%n", toHexString(sha1.digest()));
            md5.update(cert.getEncoded());
            System.out.printf("   md5:     %s%n%n", toHexString(md5.digest()));
        }

        int indexToAdd;
        if (isQuiet) {
            indexToAdd = 0;
            System.out.println("Adding first certificate to trusted keystore.");
        } else {
            System.out.print("Enter certificate to add to trusted keystore or 'q' to quit [1]: ");
            var line = new BufferedReader(new InputStreamReader(System.in)).readLine().trim();
            if (line.equalsIgnoreCase("q")) {
                System.out.println("KeyStore not changed.");
                return;
            }
            try {
                indexToAdd = line.isEmpty() ? 0 : Integer.parseInt(line) - 1;
            } catch (NumberFormatException e) {
                System.out.println("KeyStore not changed.");
                return;
            }
        }

        var cert = chain[indexToAdd];
        var alias = host + "-" + (indexToAdd + 1);
        ks.setCertificateEntry(alias, cert);

        try (OutputStream out = new FileOutputStream("jssecacerts")) {
            ks.store(out, passphrase);
        }

        System.out.printf("%nAdded certificate to keystore 'jssecacerts' using alias '%s'%n", alias);
        System.out.println(cert);
    }

    private static String toHexString(byte[] bytes) {
        var sb = new StringBuilder(bytes.length * 3);
        for (var b : bytes) {
            sb.append("%02x ".formatted(b & 0xff));
        }
        return sb.toString().trim();
    }

    private static class SavingTrustManager implements X509TrustManager {
        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }
}
