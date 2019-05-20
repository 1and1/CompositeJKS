# Changes in this fork

This fork fixes some issues of the original library ([#4](https://github.com/1and1/CompositeJKS/issues/4) and [#7](https://github.com/1and1/CompositeJKS/issues/7)) introduces a new Builder API with `SslContextBuilder.builder()` which allows more flexible configuration ([#6](https://github.com/1and1/CompositeJKS/issues/6)).

Example 1:
```
SslContextBuilder.builder()
                 .keyStoreFromFile("key store path without pwd")
                 .usingProtocol("SSL")
                 .usingSunX509()
                 .usingKeyManagerPassword("key manager pwd")
                 .buildMergedWithSystemAndSetDefault();
```

Example 2:
```
SslContextBuilder.builder()
                 .keyStoreFromFile(keyStorePath, keyStorePwd)
                 .usingTLS()
                 .usingDefaultAlgorithm()
                 .usingKeyManagerPasswordFromKeyStore()
                 .buildMergedWithSystem();
```

*Below is original README*

------

# CompositeJKS

Load a custom [Java KeyStore](https://docs.oracle.com/cd/E19509-01/820-3503/ggfen/index.html) into the SSL Context without replacing the system CA list.

To use this library, add the following to your Maven `pom.xml`:
```xml
<dependency>
  <groupId>com.oneandone</groupId>
  <artifactId>composite-jks</artifactId>
  <version>1.0</version>
</dependency>
```


## Usecase samples

CompositeJKS allows you to load a custom Java KeyStore into the SSL Context without replacing the system CA list. The system and the custom KeyStores are merged into a composite view:

```java
SslContextUtils.mergeWithSystem("/path/to/my/cacerts");
```

CompositeJKS also supports loading JKS files embedded in the JAR. Place your file in `src/main/resources/` to let Maven embed it and then use a call like:

```java
SslContextUtils.mergeWithSystem(
        getClass().getClassLoader().getResourceAsStream("keystore.jks"));
```


## The full story

Many companies host their own internal Certificate Authority (CA). These services issues X.509 certificates, e.g. for use in HTTPS connections. In order for web browsers and programmatic clients to trust connections to servers using such internal certificates, the appropriate root certificate needs to be imported into a "trusted root certificates" list.

The precise location and format of this list depends on the operating system, programming language and tool in use. For example, Internet Explorer and Google Chrome use the Windows certificate store when running on Windows while Mozilla Firefox uses its own private certificate store regardless of the operating system is running on.

Here, I would like to illustrate the particular challenges that arise when consuming internally-signed web-services in Java clients. Like Mozilla Firefox, Java uses its own certificate store rather than relying on an operating system implementation.
On Debian-based Linux distributions this file is usually located at `/etc/ssl/certs/java/cacerts`. On Windows the file can be found at path like `C:\Program Files\Java\jre1.8.0_77\lib\security\cacerts`.

These files use the Java KeyStore file format and can be modified using the `keytool` command-line tool. To add your own CA to the list of trusted roots you can run:

```
keytool -import -trustcacerts -file yourca.pem -alias yourca -keystore [Location of the certificate store as described above]
```

When prompted for a password use the default password set by Java: `changeit`

Changing this password is neither required nor recommended, since this particular Java KeyStore file only contains public keys of CAs and therefore stores no private data that required protection.

Unfortunately, there are a few problems with modifying this global KeyStore. On Windows installation of new Java versions will replace the modified file with the default again. On both Windows and Linux this modification requires administrative privileges. These issues motivate the need for a way to apply application-specific modifications to the list of trusted CAs.

The Java system property `javax.net.ssl.trustStore` can be used to specify an alternate path to load the cacerts file. You can create your own local copy of the default file and apply modifications to it using keytool. Then you can launch your application like this:

```
java -Djavax.net.ssl.trustStore=/path/to/my/cacerts -jar myapp.jar
```

If the application in question is a web-service running in Tomcat you can instead add this line to `/etc/default/tomcat8`:

```
JAVA_OPTS="${JAVA_OPTS} -Djavax.net.ssl.trustStore=/path/to/my/cacerts"
```

Another possibility is to set the Java system property within the startup code of the application itself using:

```
System.setProperty("javax.net.ssl.trustStore", "/path/to/my/cacerts");
```

Note that this last option requires the KeyStore to be a real file on-disk and not a file embedded within a JAR.

All of the aforementioned options have one major drawback: By effectively forking the upstream default cacerts file your application does not get any future updates to "public" CAs. Similarly, application-specific KeyStores will not include any customizations administrators make to the global KeyStore. CompositeJKS fixes all this by allowing you to load a custom Java KeyStore into the SSL Context without replacing the system CA list.
