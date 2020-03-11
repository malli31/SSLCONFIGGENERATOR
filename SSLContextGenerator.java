

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.jboss.logging.Logger;


public class SSLContextGenerator {
    static Map<String, TrustManager[]> trustManagersMap;
    static Map<String, SSLContext> sslContextMap;
    private static final Logger log = Logger.getLogger(SSLContextGenerator.class);

    static {
        trustManagersMap = new HashMap<String, TrustManager[]>();
        sslContextMap = new HashMap<String, SSLContext>();

    }

    public static void GenerateSSLContextForURL(String pathToKey, String keyFilePassword,
        String pathToCert, String pathToCACert, String url)
    // throws KeyStoreException, CertificateException,
    // InvalidKeySpecException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException,
    // KeyManagementException
    {
        log.info("malli: inside generate ssl");
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);//Make an empty store
            FileInputStream fis = new FileInputStream(pathToCert);
            BufferedInputStream bis = new BufferedInputStream(fis);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            log.info("malli: inside generate ssl");
            Certificate cert = null;
            if (bis.available() > 0) {
                log.info("malli: inside while bis");
                cert = cf.generateCertificate(bis);
            }
            log.info("malli: outside  bis");
            PrivateKey privateKey = createPrivateKeyFromPemFile(pathToKey);
            keyStore.setKeyEntry("caapmkey", privateKey, keyFilePassword.toCharArray(),
                new Certificate[]{cert});
            log.info("malli: after privatekey");
            FileInputStream myTrustedCAFileContent = new FileInputStream(pathToCACert);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate myCAPublicKey = (X509Certificate) certificateFactory
                .generateCertificate(myTrustedCAFileContent);

            KeyStore trustedStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustedStore.load(null);
            trustedStore.setCertificateEntry(myCAPublicKey.getSubjectX500Principal().getName(),
                myCAPublicKey);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustedStore);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, "".toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagers, null);
            log.info("malli: before adding to map");
            sslContextMap.put(url, sslContext);
            trustManagersMap.put(url, trustManagers);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            log.info("malli: InvalidKeySpecException "+e);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            log.info("malli: InvalidKeySpecException "+e);
        } catch (KeyManagementException e) {
            e.printStackTrace();
            log.info("malli: InvalidKeySpecException "+e);
        } catch (CertificateException e) {
            e.printStackTrace();
            log.info("malli: InvalidKeySpecException "+e);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            log.info("malli: InvalidKeySpecException "+e);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
            log.info("malli: InvalidKeySpecException "+e);
        } catch (IOException e) {
            e.printStackTrace();
            log.info("malli: IOException "+e);
        } catch (Exception e) {
            e.printStackTrace();
            log.info("malli: Exception "+e);
        }


    }

    public OkHttpClient getOkhttpsCLient(String url) {
        TrustManager[] trustManagers = trustManagersMap.get(url);
        SSLContext sslContext = sslContextMap.get(url);
        X509TrustManager defaultTrustManager = null;
        for (int i = 0; i < trustManagers.length; i++) {
            if (trustManagers[i] instanceof X509TrustManager) {
                defaultTrustManager = (X509TrustManager) trustManagers[i];

            }
        }
        OkHttpClient client = new OkHttpClient.Builder()
            .sslSocketFactory(sslContext.getSocketFactory(), defaultTrustManager).build();
        return client;
    }

    private static PrivateKey createPrivateKeyFromPemFile(
        final String keyFileName) throws IOException, InvalidKeySpecException,
        NoSuchAlgorithmException {
        log.info("malli: inside privatekey");
       // Security.addProvider(new BouncyCastleProvider());
        PEMParser pemParser = new PEMParser(new FileReader(keyFileName));
        Object object = pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        KeyPair kp;
        if (object instanceof PEMEncryptedKeyPair) {
            // Encrypted key - we will use provided password
            PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) object;
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder()
                .build("".toCharArray());
            kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));
        } else {
            // Unencrypted key - no password needed
            PEMKeyPair ukp = (PEMKeyPair) object;
            kp = converter.getKeyPair(ukp);
        }
        KeyFactory keyFac = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKeySpec privateKey = keyFac
            .getKeySpec(kp.getPrivate(), RSAPrivateCrtKeySpec.class);
        PrivateKey privateKey1 = keyFac.generatePrivate(privateKey);
        return privateKey1;
    }
}
