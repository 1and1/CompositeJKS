package com.oneandone.compositejks;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.net.ssl.*;
import static java.util.Arrays.stream;

/**
 * Utility methods for {@link SSLContext}.
 */
public final class SslContextUtils {

    private SslContextUtils() {
    }

    /**
     * Configures the default SSL context to use a merged view of the system key
     * store and a custom key store.
     *
     * @param keyStore The custom key store.
     * @throws GeneralSecurityException
     */
    public static void mergeWithSystem(KeyStore keyStore)
            throws GeneralSecurityException {
        SSLContext.setDefault(buildMergedWithSystem(keyStore));
    }

    /**
     * Configures the default SSL context to use a merged view of the system key
     * store and a custom key store.
     *
     * @param keyStoreStream A byte stream containing the custom key store. Must
     * have no passphrase.
     * @throws GeneralSecurityException
     * @throws java.io.IOException
     */
    public static void mergeWithSystem(InputStream keyStoreStream)
            throws GeneralSecurityException, IOException {
        mergeWithSystem(KeyStoreLoader.fromStream(keyStoreStream));
    }

    /**
     * Configures the default SSL context to use a merged view of the system key
     * store and a custom key store.
     *
     * @param keyStorePath The path of the file containing the custom key store.
     * Must have no passphrase.
     * @throws GeneralSecurityException
     * @throws java.io.IOException
     */
    public static void mergeWithSystem(String keyStorePath)
            throws GeneralSecurityException, IOException {
        mergeWithSystem(KeyStoreLoader.fromFile(keyStorePath));
    }

    /**
     * The key manager algorithm to use for X509. You may need to modify this
     * if you are using a non-Oracle JDK.
     */
    public static String X509Algorithm = "SunX509";

    /**
     * Generates an SSL context that uses a merged view of the system key store
     * and a custom key store.
     *
     * @param keyStore The custom key store.
     * @return The SSL context
     * @throws GeneralSecurityException
     */
    public static SSLContext buildMergedWithSystem(KeyStore keyStore)
            throws GeneralSecurityException {
        String defaultAlgorithm = KeyManagerFactory.getDefaultAlgorithm();

        KeyManager[] keyManagers = {new CompositeX509KeyManager(
            getSystemKeyManager(X509Algorithm, keyStore, null),
            getSystemKeyManager(defaultAlgorithm, null, null))};

        TrustManager[] trustManagers = {new CompositeX509TrustManager(
            getSystemTrustManager(X509Algorithm, keyStore),
            getSystemTrustManager(defaultAlgorithm, null))};

        SSLContext context = SSLContext.getInstance("SSL");
        context.init(keyManagers, trustManagers, null);
        return context;
    }

    public static X509KeyManager getSystemKeyManager(String algorithm, KeyStore keystore, char[] password)
            throws GeneralSecurityException {
        KeyManagerFactory factory = KeyManagerFactory.getInstance(algorithm);
        factory.init(keystore, password);
        return (X509KeyManager) stream(factory.getKeyManagers())
                .filter(x -> x instanceof X509KeyManager)
                .findFirst().orElse(null);
    }

    public static X509TrustManager getSystemTrustManager(String algorithm, KeyStore keystore)
            throws GeneralSecurityException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(algorithm);
        factory.init(keystore);
        return (X509TrustManager) stream(factory.getTrustManagers())
                .filter(x -> x instanceof X509TrustManager)
                .findFirst().orElse(null);
    }
}
