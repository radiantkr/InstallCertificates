# InstallCertificates

## Usage

Need to compile, first:
```
javac InstallCertificateToKeystore.java
```

>**Note** since Java 11, you can run it directly without compiling it first:

```
java --source 11 InstallCertificateToKeystore.java <args>
```


### Access server, and retrieve certificate (accept default certificate 1)

```
java InstallCertificateToKeystore [--proxy=proxyHost:proxyPort] <host>[:port] [passphrase]
e.g.: java InstallCertificateToKeystore <TokenHost>:<Port>![image](https://github.com/user-attachments/assets/33442d06-f3a1-4614-84d5-c7fe595d3968)
```


### Extract certificate from created jssecacerts keystore

```
keytool -exportcert -alias [host]-1 -keystore jssecacerts -storepass changeit -file [host].cer
e.g.: keytool -exportcert -alias <Alias_Name> -keystore jssecacerts -storepass changeit -file <Certificate Path>
```


### Import certificate into system keystore

```
sudo keytool -importcert -alias [host] -keystore [path to system cacerts] -storepass changeit -file [host].cer
e.g.:sudo keytool -importcert -alias <Alias_Name> -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit -file <Certificate Path>
```

Hint: `keystore` system cacerts path should be located in `$JAVA_HOME/lib/security/cacerts` if your `$JAVA_HOME` env var is set.

>**Note** since Java 11, you can use the `-cacerts` flag instead of `-keystore [cacerts path]`

