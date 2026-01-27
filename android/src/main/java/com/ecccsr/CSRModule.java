package com.ecccsr;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class CSRModule extends ReactContextBaseJavaModule {

    private static final String MODULE_NAME = "CSRModule";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String SOFTWARE_KEYSTORE_FILE = "software_keys.p12";
    private static final String DEFAULT_COUNTRY = "US";
    private static final String DEFAULT_STATE = "Colorado";
    private static final String DEFAULT_LOCALITY = "Denver";
    private static final String DEFAULT_ORGANIZATION = "MyOrg";
    private static final String DEFAULT_ORGANIZATIONAL_UNIT = "MyOrgUnit";
    private static final String DEFAULT_IP_ADDRESS = "10.10.10.10";
    private static final String DEFAULT_ECC_CURVE = "secp384r1";

    public CSRModule(ReactApplicationContext reactContext) {
        super(reactContext);
        // Only add BC provider if not already present
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public String getName() {
        return MODULE_NAME;
    }

    /**
     * Custom ContentSigner implementation for Android Keystore
     */
    private static class AndroidKeystoreContentSigner implements ContentSigner {
        private final ByteArrayOutputStream outputStream;
        private final AlgorithmIdentifier sigAlgId;
        private final Signature signature;

        public AndroidKeystoreContentSigner(PrivateKey privateKey, String algorithm) throws Exception {
            this.outputStream = new ByteArrayOutputStream();
            this.sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
            this.signature = Signature.getInstance(algorithm);
            this.signature.initSign(privateKey);
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return sigAlgId;
        }

        @Override
        public OutputStream getOutputStream() {
            return outputStream;
        }

        @Override
        public byte[] getSignature() {
            try {
                signature.update(outputStream.toByteArray());
                return signature.sign();
            } catch (Exception e) {
                throw new RuntimeException("Failed to sign", e);
            }
        }
    }

    /**
     * Create a self-signed certificate for software keystore
     */
    private X509Certificate createSelfSignedCertificate(KeyPair keyPair, String subjectDN) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 year validity

        X500Name subject = new X500Name(subjectDN);
        BigInteger serialNumber = BigInteger.valueOf(now);

        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                subject,
                serialNumber,
                startDate,
                endDate,
                subject,
                publicKeyInfo);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(signer));
    }

    @ReactMethod
    public void generateCSR(ReadableMap params, Promise promise) {
        try {
            // Extract parameters
            String country = params.hasKey("country") ? params.getString("country") : DEFAULT_COUNTRY;
            String state = params.hasKey("state") ? params.getString("state") : DEFAULT_STATE;
            String locality = params.hasKey("locality") ? params.getString("locality") : DEFAULT_LOCALITY;
            String organization = params.hasKey("organization") ? params.getString("organization")
                    : DEFAULT_ORGANIZATION;
            String organizationalUnit = params.hasKey("organizationalUnit") ? params.getString("organizationalUnit")
                    : DEFAULT_ORGANIZATIONAL_UNIT;
            String commonName = params.hasKey("commonName") ? params.getString("commonName") : "";
            String serialNumber = params.hasKey("serialNumber") ? params.getString("serialNumber") : "";
            String ipAddress = params.hasKey("ipAddress") ? params.getString("ipAddress") : DEFAULT_IP_ADDRESS;
            String dnsName = params.hasKey("dnsName") ? params.getString("dnsName") : null;
            String curve = params.hasKey("curve") ? params.getString("curve") : DEFAULT_ECC_CURVE;
            String phoneInfo = params.hasKey("phoneInfo") ? params.getString("phoneInfo") : null;
            String privateKeyAlias = params.hasKey("privateKeyAlias") ? params.getString("privateKeyAlias") : null;
            
            // NEW: Flag to choose hardware vs software key
            boolean useHardwareKey = params.hasKey("useHardwareKey") ? params.getBoolean("useHardwareKey") : true;

            if (privateKeyAlias == null || privateKeyAlias.isEmpty()) {
                promise.reject("MISSING_ALIAS", "privateKeyAlias is required");
                return;
            }

            // Validate curve
            if (!curve.equals("secp256r1") && !curve.equals("secp384r1") && !curve.equals("secp521r1")) {
                promise.reject("INVALID_CURVE", "Curve must be one of: secp256r1, secp384r1, secp521r1");
                return;
            }

            String keystoreCurve;
            switch (curve) {
                case "secp256r1":
                    keystoreCurve = "secp256r1";
                    break;
                case "secp384r1":
                    keystoreCurve = "secp384r1";
                    break;
                case "secp521r1":
                    keystoreCurve = "secp521r1";
                    break;
                default:
                    keystoreCurve = "secp384r1";
            }

            KeyPair keyPair;
            PrivateKey privateKey;
            PublicKey publicKey;

            if (useHardwareKey) {
                // HARDWARE-BACKED KEY
                Log.d(MODULE_NAME, "🔐 Generating HARDWARE-BACKED key pair");
                
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC,
                        ANDROID_KEYSTORE);

                int purposes = KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                    purposes |= KeyProperties.PURPOSE_AGREE_KEY;
                    Log.d(MODULE_NAME, "✓ Including PURPOSE_AGREE_KEY (Android 12+)");
                } else {
                    Log.d(MODULE_NAME, "⚠ Skipping PURPOSE_AGREE_KEY (requires Android 12+, current API: " + 
                          android.os.Build.VERSION.SDK_INT + ")");
                }

                KeyGenParameterSpec.Builder specBuilder = new KeyGenParameterSpec.Builder(
                        privateKeyAlias,
                        purposes)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec(keystoreCurve))
                        .setDigests(
                                KeyProperties.DIGEST_SHA256,
                                KeyProperties.DIGEST_SHA384,
                                KeyProperties.DIGEST_SHA512)
                        .setUserAuthenticationRequired(false);

                keyPairGenerator.initialize(specBuilder.build());
                keyPair = keyPairGenerator.generateKeyPair();
                
            } else {
                // SOFTWARE KEY (using BouncyCastle)
                Log.d(MODULE_NAME, "💾 Generating SOFTWARE key pair (BouncyCastle)");
                
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
                ECGenParameterSpec ecSpec = new ECGenParameterSpec(keystoreCurve);
                keyPairGenerator.initialize(ecSpec, new SecureRandom());
                keyPair = keyPairGenerator.generateKeyPair();
                
                // Store in a PKCS12 keystore
                KeyStore softwareKeyStore;
                String keystorePath = getReactApplicationContext().getFilesDir() + "/" + SOFTWARE_KEYSTORE_FILE;
                
                try {
                    // Try to load existing keystore
                    FileInputStream fis = new FileInputStream(keystorePath);
                    softwareKeyStore = KeyStore.getInstance("PKCS12");
                    softwareKeyStore.load(fis, "".toCharArray());
                    fis.close();
                    Log.d(MODULE_NAME, "Loaded existing software keystore");
                } catch (Exception e) {
                    // Create new keystore
                    softwareKeyStore = KeyStore.getInstance("PKCS12");
                    softwareKeyStore.load(null, null);
                    Log.d(MODULE_NAME, "Created new software keystore");
                }
                
                // Create a self-signed cert (required by keystore)
                String tempSubject = "CN=Temp-" + privateKeyAlias;
                X509Certificate selfSignedCert = createSelfSignedCertificate(keyPair, tempSubject);
                
                // Store the key
                softwareKeyStore.setKeyEntry(
                    privateKeyAlias,
                    keyPair.getPrivate(),
                    "".toCharArray(),
                    new java.security.cert.Certificate[] { selfSignedCert }
                );
                
                // Save keystore to file
                FileOutputStream fos = new FileOutputStream(keystorePath);
                softwareKeyStore.store(fos, "".toCharArray());
                fos.close();
                
                Log.d(MODULE_NAME, "✓ Software keystore saved to: " + keystorePath);
            }

            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();

            Log.d(MODULE_NAME, "✓ Key pair generated with alias: " + privateKeyAlias);
            Log.d(MODULE_NAME, "  Type: " + (useHardwareKey ? "Hardware-backed (AndroidKeyStore)" : "Software (BouncyCastle/PKCS12)"));
            Log.d(MODULE_NAME, "  Curve: " + keystoreCurve);

            // Build the subject DN
            StringBuilder subjectBuilder = new StringBuilder();
            subjectBuilder.append("C=").append(country);
            subjectBuilder.append(", ST=").append(state);
            subjectBuilder.append(", L=").append(locality);
            subjectBuilder.append(", O=").append(organization);
            subjectBuilder.append(", OU=").append(organizationalUnit);
            subjectBuilder.append(", CN=").append(commonName);
            if (!serialNumber.isEmpty()) {
                subjectBuilder.append(", serialNumber=").append(serialNumber);
            }

            X500Name subject = new X500Name(subjectBuilder.toString());

            // Create CSR builder
            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);

            // Create extensions
            ExtensionsGenerator extGen = new ExtensionsGenerator();

            // Add Key Usage (critical): Digital Signature, Key Agreement
            KeyUsage keyUsage = new KeyUsage(
                    KeyUsage.digitalSignature | KeyUsage.keyAgreement);
            extGen.addExtension(Extension.keyUsage, true, keyUsage);

            // Add Extended Key Usage: TLS Web Client Authentication
            ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
                    KeyPurposeId.id_kp_clientAuth);
            extGen.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);

            // Build Subject Alternative Names
            List<GeneralName> sanList = new ArrayList<>();
            sanList.add(new GeneralName(GeneralName.iPAddress, ipAddress));

            if (dnsName != null && !dnsName.trim().isEmpty()) {
                try {
                    String[] dnsNames = dnsName.split(",");
                    for (String dns : dnsNames) {
                        String trimmedDns = dns.trim();
                        if (!trimmedDns.isEmpty()) {
                            sanList.add(new GeneralName(GeneralName.dNSName, trimmedDns));
                            Log.d(MODULE_NAME, "Added DNS name to SAN: " + trimmedDns);
                        }
                    }
                } catch (Exception e) {
                    Log.e(MODULE_NAME, "Failed to add DNS name to SAN", e);
                }
            }

            if (phoneInfo != null && !phoneInfo.trim().isEmpty()) {
                try {
                    String uriValue = "phone:" + phoneInfo.trim();
                    sanList.add(new GeneralName(GeneralName.uniformResourceIdentifier, uriValue));
                    Log.d(MODULE_NAME, "Successfully added phoneInfo as URI: " + uriValue);
                } catch (Exception e) {
                    Log.e(MODULE_NAME, "Failed to add phone info to SAN", e);
                }
            }

            GeneralName[] sanArray = sanList.toArray(new GeneralName[0]);
            GeneralNames subjectAltNames = new GeneralNames(sanArray);
            extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);

            csrBuilder.addAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    extGen.generate());

            // Sign the CSR
            ContentSigner signer;
            if (useHardwareKey) {
                signer = new AndroidKeystoreContentSigner(privateKey, "SHA256withECDSA");
            } else {
                signer = new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider("BC")
                        .build(privateKey);
            }

            PKCS10CertificationRequest csr = csrBuilder.build(signer);

            // Convert CSR to PEM format
            StringWriter csrWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(csrWriter);
            pemWriter.writeObject(csr);
            pemWriter.close();
            String csrPem = csrWriter.toString();

            // Prepare response
            com.facebook.react.bridge.WritableMap response = com.facebook.react.bridge.Arguments.createMap();
            response.putString("csr", csrPem);
            response.putString("privateKeyAlias", privateKeyAlias);
            response.putString("publicKey", Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP));
            response.putBoolean("isHardwareBacked", useHardwareKey && isHardwareBacked(privateKeyAlias));
            response.putBoolean("useHardwareKey", useHardwareKey);

            Log.d(MODULE_NAME, "✅ CSR generated successfully");

            promise.resolve(response);

        } catch (Exception e) {
            Log.e(MODULE_NAME, "❌ CSR generation failed", e);
            promise.reject("CSR_GENERATION_ERROR", "Failed to generate CSR: " + e.getMessage(), e);
        }
    }

    @ReactMethod
    public void deleteKey(String privateKeyAlias, Promise promise) {
        try {
            // Try to delete from hardware keystore
            try {
                KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
                keyStore.load(null);
                if (keyStore.containsAlias(privateKeyAlias)) {
                    keyStore.deleteEntry(privateKeyAlias);
                    Log.d(MODULE_NAME, "✓ Deleted hardware key: " + privateKeyAlias);
                }
            } catch (Exception e) {
                Log.d(MODULE_NAME, "No hardware key to delete");
            }
            
            // Try to delete from software keystore
            try {
                String keystorePath = getReactApplicationContext().getFilesDir() + "/" + SOFTWARE_KEYSTORE_FILE;
                FileInputStream fis = new FileInputStream(keystorePath);
                KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");
                softwareKeyStore.load(fis, "".toCharArray());
                fis.close();
                
                if (softwareKeyStore.containsAlias(privateKeyAlias)) {
                    softwareKeyStore.deleteEntry(privateKeyAlias);
                    
                    // Save updated keystore
                    FileOutputStream fos = new FileOutputStream(keystorePath);
                    softwareKeyStore.store(fos, "".toCharArray());
                    fos.close();
                    
                    Log.d(MODULE_NAME, "✓ Deleted software key: " + privateKeyAlias);
                }
            } catch (Exception e) {
                Log.d(MODULE_NAME, "No software key to delete");
            }
            
            promise.resolve(true);
        } catch (Exception e) {
            Log.e(MODULE_NAME, "❌ Failed to delete key", e);
            promise.reject("DELETE_KEY_ERROR", "Failed to delete key: " + e.getMessage(), e);
        }
    }

    @ReactMethod
    public void keyExists(String privateKeyAlias, Promise promise) {
        try {
            // Check hardware keystore
            try {
                KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
                keyStore.load(null);
                if (keyStore.containsAlias(privateKeyAlias)) {
                    promise.resolve(true);
                    return;
                }
            } catch (Exception e) {
                // Continue to check software keystore
            }
            
            // Check software keystore
            try {
                String keystorePath = getReactApplicationContext().getFilesDir() + "/" + SOFTWARE_KEYSTORE_FILE;
                FileInputStream fis = new FileInputStream(keystorePath);
                KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");
                softwareKeyStore.load(fis, "".toCharArray());
                fis.close();
                
                boolean exists = softwareKeyStore.containsAlias(privateKeyAlias);
                promise.resolve(exists);
            } catch (Exception e) {
                promise.resolve(false);
            }
        } catch (Exception e) {
            promise.reject("KEY_EXISTS_ERROR", "Failed to check key existence: " + e.getMessage(), e);
        }
    }

    @ReactMethod
    public void getPublicKey(String privateKeyAlias, Promise promise) {
        try {
            // Try hardware keystore first
            try {
                KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
                keyStore.load(null);

                if (keyStore.containsAlias(privateKeyAlias)) {
                    KeyStore.Entry entry = keyStore.getEntry(privateKeyAlias, null);
                    if (entry instanceof KeyStore.PrivateKeyEntry) {
                        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                        PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();
                        String publicKeyBase64 = Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
                        promise.resolve(publicKeyBase64);
                        return;
                    }
                }
            } catch (Exception e) {
                // Continue to software keystore
            }
            
            // Try software keystore
            String keystorePath = getReactApplicationContext().getFilesDir() + "/" + SOFTWARE_KEYSTORE_FILE;
            FileInputStream fis = new FileInputStream(keystorePath);
            KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");
            softwareKeyStore.load(fis, "".toCharArray());
            fis.close();
            
            if (softwareKeyStore.containsAlias(privateKeyAlias)) {
                KeyStore.Entry entry = softwareKeyStore.getEntry(privateKeyAlias, new KeyStore.PasswordProtection("".toCharArray()));
                if (entry instanceof KeyStore.PrivateKeyEntry) {
                    KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                    PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();
                    String publicKeyBase64 = Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
                    promise.resolve(publicKeyBase64);
                    return;
                }
            }
            
            promise.reject("KEY_NOT_FOUND", "Key with alias '" + privateKeyAlias + "' not found");
            
        } catch (Exception e) {
            promise.reject("GET_PUBLIC_KEY_ERROR", "Failed to get public key: " + e.getMessage(), e);
        }
    }

    private boolean isHardwareBacked(String privateKeyAlias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);

            KeyStore.Entry entry = keyStore.getEntry(privateKeyAlias, null);
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;

                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                    try {
                        KeyFactory factory = KeyFactory.getInstance(
                                privateKeyEntry.getPrivateKey().getAlgorithm(),
                                ANDROID_KEYSTORE);
                        KeyInfo keyInfo = factory.getKeySpec(
                                privateKeyEntry.getPrivateKey(),
                                KeyInfo.class);
                        return keyInfo.isInsideSecureHardware();
                    } catch (Exception e) {
                        Log.w(MODULE_NAME, "Could not determine hardware backing status", e);
                        return true;
                    }
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
