package com.oneandone.compositejks;

import java.util.List;
import java.util.function.Function;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import javax.net.ssl.X509TrustManager;
import static java.util.Arrays.asList;
import static java.util.Arrays.stream;

/**
 * Merges multiple {@link X509TrustManager}s into a delegating composite.
 */
public class CompositeX509TrustManager implements X509TrustManager {

    private final List<X509TrustManager> children;

    public CompositeX509TrustManager(X509TrustManager... children) {
        this.children = asList(children);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateException lastError = null;
        for (X509TrustManager trustManager : children) {
            try {
                trustManager.checkClientTrusted(chain, authType);
                return;
            } catch (CertificateException ex) {
                lastError = ex;
            }
        }

        if (lastError != null) {
            throw lastError;
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateException lastError = null;
        for (X509TrustManager trustManager : children) {
            try {
                trustManager.checkServerTrusted(chain, authType);
                return;
            } catch (CertificateException ex) {
                lastError = ex;
            }
        }

        if (lastError != null) {
            throw lastError;
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return merge(x -> x.getAcceptedIssuers());
    }

    private X509Certificate[] merge(Function<X509TrustManager, X509Certificate[]> map) {
        return children.stream().flatMap(x -> stream(map.apply(x)))
                .toArray(x -> new X509Certificate[x]);
    }
}
