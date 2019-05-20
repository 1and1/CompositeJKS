package com.oneandone.compositejks;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Merges multiple {@link X509TrustManager}s into a delegating composite.
 */
public class CompositeX509TrustManager implements X509TrustManager {

    private final List<X509TrustManager> children;

    public CompositeX509TrustManager(List<X509TrustManager> children) {
        this.children = children;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(x -> x.checkClientTrusted(chain, authType));
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(x -> x.checkServerTrusted(chain, authType));
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return children.stream()
                       .flatMap(x -> Arrays.stream(x.getAcceptedIssuers()))
                       .toArray(X509Certificate[]::new);
    }

    private void checkTrusted(ThrowingProcessor processor) throws CertificateException {
        CertificateException lastError = null;
        for (X509TrustManager manager : children) {
            try {
                processor.process(manager);
                return;
            } catch (CertificateException ex) {
                lastError = ex;
            }
        }

        if (lastError != null) {
            throw lastError;
        }
    }

    private interface ThrowingProcessor {

        void process(X509TrustManager manager) throws CertificateException;
    }
}
