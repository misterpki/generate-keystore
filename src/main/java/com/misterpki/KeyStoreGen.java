package com.misterpki;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import javax.crypto.KeyGenerator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class KeyStoreGen {

  /**
   * Generates a PKCS12 keystore including both a symmetric and asymmetric key entry.
   *
   * @param password The password to be set on the keystore and each key entry.
   *
   * @return new keystore
   */
  public static KeyStore generatePKCS12KeyStore(final String password)
    throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException, OperatorCreationException
  {
    final KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, password.toCharArray());

    // Create Symmetric key entry
    final KeyGenerator aesGenerator = KeyGenerator.getInstance("AES");
    aesGenerator.init(128);
    final KeyStore.SecretKeyEntry aesSecretKey = new KeyStore.SecretKeyEntry(aesGenerator.generateKey());
    final KeyStore.ProtectionParameter aesSecretKeyPassword =
      new KeyStore.PasswordProtection(password.toCharArray());
    // Add symmetric key to keystore
    keyStore.setEntry("symm-key", aesSecretKey, aesSecretKeyPassword);

    // Create Asymmetric key pair
    final KeyPair asymmetricKeys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    final KeyStore.PrivateKeyEntry privateKey =
      new KeyStore.PrivateKeyEntry(
        asymmetricKeys.getPrivate(),
        new X509Certificate[]{generateX509Certificate(asymmetricKeys)});
    final KeyStore.ProtectionParameter privateKeyPassword =
      new KeyStore.PasswordProtection(password.toCharArray());
    // Add asymmetric key to keystore
    keyStore.setEntry("asymm-key", privateKey, privateKeyPassword);

    return keyStore;
  }

  /**
   * Generates a self signed certificate.
   *
   * @param keyPair used for signing the certificate
   *
   * @return self-signed X509Certificate
   */
  private static X509Certificate generateX509Certificate(final KeyPair keyPair)
    throws OperatorCreationException, CertificateException, CertIOException
  {
    final Instant now = Instant.now();
    final Date notBefore = Date.from(now);
    final Date notAfter = Date.from(now.plus(Duration.ofDays(1)));

    final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
    final String dn = "CN=asymm-cn";

    final X500Name x500Name = new X500Name(RFC4519Style.INSTANCE, dn);
    final X509v3CertificateBuilder certificateBuilder =
      new JcaX509v3CertificateBuilder(x500Name,
        BigInteger.valueOf(now.toEpochMilli()),
        notBefore,
        notAfter,
        x500Name,
        keyPair.getPublic())
        .addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

    return new JcaX509CertificateConverter()
      .setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
  }
}
