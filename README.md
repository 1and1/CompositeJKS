# CompositeJKS

Load a custom Java Keystore into the SSL Context without replacing the system CA list.

Maven artifact:
* `com.oneandone:composite-jks`


## Usecase sample

```java
SslContextUtils.mergeWithSystem(
        getClass().getClassLoader().getResourceAsStream("keystore.jks"));
```
