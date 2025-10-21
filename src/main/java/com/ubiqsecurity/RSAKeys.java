package com.ubiqsecurity;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.io.Writer;

import java.security.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import java.util.Base64;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

public abstract class RSAKeys {

  static private BouncyCastleProvider bcProvider = null;

  private static BouncyCastleProvider getProvider() {
    if (bcProvider == null) {
      bcProvider = new BouncyCastleProvider();
    }
    return bcProvider;
  }

  public static java.security.KeyPair generateKeyPair(String type, Integer bits) throws java.security.NoSuchAlgorithmException {

    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(getProvider());
    } 

    // Generate 4096-bit RSA key pair
    KeyPairGenerator generator = KeyPairGenerator.getInstance(type);
    generator.initialize(bits);
    KeyPair keyPair = generator.generateKeyPair();
    return keyPair;
  }

  public static String generateCsr(KeyPair keyPair) throws OperatorCreationException, IOException{
    byte[] cn = new byte[18];
    SecureRandom random = new SecureRandom();
    random.nextBytes(cn);

    X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
    builder.addRDN(BCStyle.CN, new String(Base64.getEncoder().encode(cn))); // commonName
    builder.addRDN(BCStyle.C, "US"); // CountryName
    builder.addRDN(BCStyle.ST, "California"); // StateOrProvinceName
    builder.addRDN(BCStyle.L, "San Diego"); // localityName
    builder.addRDN(BCStyle.O, "Ubiq Security, Inc."); // OrganizationName
    builder.addRDN(BCStyle.OU, "Ubiq Platform"); // OU


    PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
      builder.build(),
      keyPair.getPublic()
    );

    JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
    contentSignerBuilder.setProvider(getProvider());
    ContentSigner contentSigner = contentSignerBuilder.build(keyPair.getPrivate());

    // Build the CSR
    PKCS10CertificationRequest csr = csrBuilder.build(contentSigner);

    // Convert the CSR to PEM format
    Writer writer = new StringWriter();
    JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
    pemWriter.writeObject(csr);
    pemWriter.close();

    return writer.toString();
  }


}
