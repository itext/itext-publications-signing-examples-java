# The Utimaco JCE Provider

The Utimaco JCE provider jar cannot be retrieved from public maven repositories; instead one has to retrieve it from the software accompanying e.g. the Utimaco Simulator used during development of these examples, see below. Beware, there may be multiple `CryptoServerJCE.jar` files included in that software package. Depending on the version of the software package the individual provider jar files include binaries for only a single OS or for multiple ones. Thus, make sure you choose the one matching your system architecture.

Also make sure you retrieve the jar from a software package matching your device. In particular there are major differences between devices running in FIPS mode and devices that don't.

Once you have found a matching `CryptoServerJCE.jar`, you can deploy it locally like this to match the assumptions in the pom files:

    mvn install:install-file -Dfile=CryptoServerJCE.jar -DgroupId=utimaco -DartifactId=CryptoServerJCE -Dversion=1.72 -Dpackaging=jar

You can find the exact version in the `META-INF\MANIFEST.MF` inside the jar. Make sure the utimaco:CryptoServerJCE version in the project POM file matches the version you have installed.

The code in this module has been tested with versions 1.69 and 1.72 of the provider.

# The Test Utimaco HSM Used

For the tests the [Utimaco Simulator](https://hsm.utimaco.com/products-hardware-security-modules/hsm-simulators/securityserver-simulator/) is used.

Using the Utimaco Administration Tools a _cryptographic user_ `JCE` with `CXI_GROUP=JCE` and HMAC password `5678` has been created.

For the Utimaco JCE driver to address the correct device, group, and user, a configuration file is required during initialization which must be located in the user's home, named <tt>CryptoServer.cfg</tt> and look like this:

    Device = 3001@127.0.0.1
    DefaultUser = JCE
    KeyGroup = JCE

A RSA keypair and a self-signed certificate then have been generated in that group using (on a single line)

    keytool.exe -providerpath lib\CryptoServerJCE.jar -providerclass CryptoServerJCE.CryptoServerProvider
                -providername CryptoServer -keystore NONE -storetype CryptoServer
                -genkeypair -alias RSAkey -keyalg RSA
                -dname "CN=mkl JCE test, OU=tests, O=mkl"

The same password has been used for the new key as for the keystore, i.e. the password of the implied user `JCE`: `5678`.