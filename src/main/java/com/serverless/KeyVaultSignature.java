package com.serverless;

import com.itextpdf.signatures.IExternalSignature;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.webkey.JsonWebKeySignatureAlgorithm;

public class KeyVaultSignature implements IExternalSignature {
  private KeyVaultClient client;
  private String keyIdentifier;

  public KeyVaultSignature(KeyVaultClient client, String keyIdentifier){
    this.client = client;
    this.keyIdentifier = keyIdentifier;
  }

  public String getEncryptionAlgorithm(){
    return "RSA";
  }

  public String getHashAlgorithm(){
    return "SHA-256";
  }

  public byte[] sign(byte[] message) throws GeneralSecurityException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(message);

    return client.sign(
      keyIdentifier,
      JsonWebKeySignatureAlgorithm.RS256,
      hash
    ).result();
  }
}
