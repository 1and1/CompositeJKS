package com.oneandone.compositejks;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * Merges multiple {@link X509KeyManager}s into a delegating composite.
 */
public class CompositeX509KeyManager implements X509KeyManager {

    private final List<X509KeyManager> children;

    public CompositeX509KeyManager(List<X509KeyManager> children) {
        this.children = children;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return getFirstNonNull(x -> x.chooseClientAlias(keyType, issuers, socket));
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return getFirstNonNull(x -> x.chooseServerAlias(keyType, issuers, socket));
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return getFirstNonNull(x -> x.getCertificateChain(alias));
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return getFirstNonNull(x -> x.getPrivateKey(alias));
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return merge(x -> x.getClientAliases(keyType, issuers));
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return merge(x -> x.getServerAliases(keyType, issuers));
    }

    private <TOut> TOut getFirstNonNull(Function<X509KeyManager, TOut> map) {
        return children.stream()
                       .map(map)
                       .filter(Objects::nonNull)
                       .findFirst()
                       .orElse(null);
    }

    private String[] merge(Function<X509KeyManager, String[]> map) {
        return children.stream()
                       .flatMap(x -> Arrays.stream(map.apply(x)))
                       .toArray(String[]::new);
    }
}
