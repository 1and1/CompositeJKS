package com.oneandone.compositejks;

import java.util.stream.Stream;
import java.util.function.Function;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509KeyManager;
import static java.util.Arrays.stream;

/**
 * Merges multiple {@link X509KeyManager}s into a delegating composite.
 */
public class CompositeX509KeyManager implements X509KeyManager {

    private final Stream<X509KeyManager> children;

    public CompositeX509KeyManager(X509KeyManager... children) {
        this.children = stream(children);
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

    private <TOut> TOut getFirstNonNull(Function<X509KeyManager, TOut> map) {
        return children.map(map)
                .filter(x -> x != null)
                .findFirst().orElse(null);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return merge(x -> x.getClientAliases(keyType, issuers));
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return merge(x -> x.getServerAliases(keyType, issuers));
    }

    private String[] merge(Function<X509KeyManager, String[]> map) {
        return children
                .flatMap(x -> stream(map.apply(x)))
                .toArray(size -> new String[size]);
    }
}
