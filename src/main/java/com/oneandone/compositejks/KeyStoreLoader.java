package com.oneandone.compositejks;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

/**
 * Utility methods for loading {@link KeyStore}s.
 *
 * @author Bastian
 */
public final class KeyStoreLoader {

    private KeyStoreLoader() {
    }

    /**
     * Loads a {@link KeyStore} from an {@link InputStream} with no passphrase.
     *
     * @param stream A byte stream containing the key store.
     * @return The newly loaded {@link KeyStore}.
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static KeyStore fromStream(InputStream stream)
            throws IOException, GeneralSecurityException {
        return fromStream(stream, null);
    }

    /**
     * Loads a {@link KeyStore} from an {@link InputStream}.
     *
     * @param stream A byte stream containing the key store.
     * @param passphrase The passphrase the stream is encrypted with.
     * @return The newly loaded {@link KeyStore}.
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static KeyStore fromStream(InputStream stream, char[] passphrase)
            throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(stream, passphrase);
        return keyStore;
    }

    /**
     * Loads a {@link KeyStore} from an on-disk file with no passphrase.
     *
     * @param path The path of the file containing the key store.
     * @return The newly loaded {@link KeyStore}.
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static KeyStore fromFile(String path)
            throws IOException, GeneralSecurityException {
        try (FileInputStream stream = new FileInputStream(path)) {
            return fromStream(stream);
        }
    }

    /**
     * Loads a {@link KeyStore} from an on-disk file.
     *
     * @param path The path of the file containing the key store.
     * @param passphrase The passphrase the file is encrypted with.
     * @return The newly loaded {@link KeyStore}.
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static KeyStore fromStream(String path, char[] passphrase)
            throws IOException, GeneralSecurityException {
        try (FileInputStream stream = new FileInputStream(path)) {
            return fromStream(stream, passphrase);
        }
    }
}
