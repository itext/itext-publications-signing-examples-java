# The PKCS#11 device used

For the tests [SoftHSM2](https://www.opendnssec.org/softhsm/), the [Utimaco Simulator](https://hsm.utimaco.com/products-hardware-security-modules/hsm-simulators/securityserver-simulator/), Belgian ID cards in ACS zetes card readers, D-Trust qualified signature cards 3.1 in Reiner SCT cyberJack e-com card readers, and the [Entrust Signing Automation Service](https://www.entrust.com/digital-security/certificate-solutions/products/digital-signing/digital-signing-as-a-service/signing-automation-service) are used as devices addressed via PKCS#11.

Installation and configuration details are explained in the `README.md` of the parallel project `com.itextpdf.signingexamples:signing-examples-pkcs11-java11` which also focuses on signing with iText via PKCS#11 but runs in a newer JRE.
