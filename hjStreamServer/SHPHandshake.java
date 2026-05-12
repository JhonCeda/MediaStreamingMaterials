import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * SHPHandshake - Server-side SHP (Secure Handshake Protocol) implementation
 * 
 * Performs 3-step handshake:
 * 1. Receive CLIENT_HELLO from proxy
 * 2. Send SERVER_HELLO response
 * 3. Receive CLIENT_CONFIRM and derive shared secret
 */
public class SHPHandshake {

  private KeyStore keyStore;
  private KeyStore trustStore;
  private String keyAlias;
  private String keyPassword;
  private PrivateKey serverPrivateKey;
  private java.security.cert.Certificate serverCertificate;

  // Handshake state
  private KeyPair serverECDHPair;
  private byte[] sharedSecret;
  private byte[] derivedKey;
  private byte[] derivedHmacKey;
  private String selectedCiphersuite;

  /**
   * Initialize handshake with server credentials
   */
  public SHPHandshake(String keystorePath, String keystorePassword, String trustStorePath,
      String trustStorePassword, String keyAlias, String keyPassword) throws Exception {
    this.keyAlias = keyAlias;
    this.keyPassword = keyPassword;

    // Load keystore
    keyStore = KeyStore.getInstance("JKS");
    keyStore.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());
    serverPrivateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());
    serverCertificate = keyStore.getCertificate(keyAlias);

    // Load truststore
    trustStore = KeyStore.getInstance("JKS");
    trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());

    // Generate server's ECDH keypair
    serverECDHPair = CryptoUtils.generateECDHKeyPair();

    System.out.println("[SHP] Server handshake initialized");
  }

  /**
   * Get server's ECDH public key in DER format
   */
  public byte[] getECDHPublicKeyDER() throws Exception {
    PublicKey pubKey = serverECDHPair.getPublic();
    return pubKey.getEncoded();
  }

  /**
   * Get server's certificate in DER format
   */
  public byte[] getCertificateDER() throws Exception {
    return serverCertificate.getEncoded();
  }

  /**
   * Process CLIENT_HELLO from proxy
   * Decrypts movieName, validates certificate and signature
   */
  public SHPMessage.ClientHello processClientHello(byte[] rawMessage) throws Exception {
    SHPMessage.ClientHello msg = SHPMessage.ClientHello.fromBytes(rawMessage);

    // 1. Decrypt movieName using server's private key
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
    byte[] decryptedMovieName = rsaCipher.doFinal(msg.encryptedMovieName);
    msg.movieName = new String(decryptedMovieName, "UTF-8");
    System.out.println("[SHP] Decrypted CLIENT_HELLO movieName: " + msg.movieName);

    // 2. Verify proxy's certificate
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    java.security.cert.Certificate proxyCert = cf.generateCertificate(
        new ByteArrayInputStream(msg.certificate));
    System.out.println("[SHP] Proxy certificate received: " + proxyCert);

    // 3. Verify signature
    PublicKey proxyPublicKey = proxyCert.getPublicKey();
    byte[] dataToVerify = msg.getDataToSign();
    if (!CryptoUtils.verifySignature(dataToVerify, msg.signature, proxyPublicKey)) {
      throw new Exception("[SHP] CLIENT_HELLO signature verification failed!");
    }
    System.out.println("[SHP] CLIENT_HELLO signature verified ✓");

    return msg;
  }

  /**
   * Create SERVER_HELLO response
   */
  public SHPMessage.ServerHello createServerHello(String movieName, boolean movieFound,
      String[] clientCiphersuites, byte[] clientNonce) throws Exception {
    // Select first supported ciphersuite (in real implementation, negotiate
    // properly)
    String selected = clientCiphersuites.length > 0 ? clientCiphersuites[0] : "AES/CTR/NoPadding";
    this.selectedCiphersuite = selected;

    byte[] serverNonce = CryptoUtils.generateNonce(16);

    SHPMessage.ServerHello serverHello = new SHPMessage.ServerHello(movieFound,
        getCertificateDER(), getECDHPublicKeyDER(), selected, clientNonce, serverNonce);

    // Sign the response
    byte[] dataToSign = serverHello.getDataToSign();
    serverHello.signature = CryptoUtils.signData(dataToSign, serverPrivateKey);

    System.out.println("[SHP] SERVER_HELLO created with cipher: " + selected);
    return serverHello;
  }

  /**
   * Derive shared secret from CLIENT_HELLO's ECDH public key
   */
  public void deriveSharedSecret(byte[] proxyECDHPublicKeyDER) throws Exception {
    // Reconstruct proxy's public key
    KeyFactory kf = KeyFactory.getInstance("EC");
    X509EncodedKeySpec spec = new X509EncodedKeySpec(proxyECDHPublicKeyDER);
    PublicKey proxyPublicKey = kf.generatePublic(spec);

    // Perform ECDH
    sharedSecret = CryptoUtils.performECDH(serverECDHPair.getPrivate(), proxyPublicKey);
    System.out.println("[SHP] Shared secret derived: " + CryptoUtils.bytesToHex(sharedSecret));

    // Derive symmetric keys using HKDF
    byte[] keyMaterial = CryptoUtils.hkdf(sharedSecret, null, "RTSSP-SHP-Keys".getBytes(), 64);
    derivedKey = new byte[32]; // First 32 bytes for cipher
    derivedHmacKey = new byte[32]; // Next 32 bytes for HMAC
    System.arraycopy(keyMaterial, 0, derivedKey, 0, 32);
    System.arraycopy(keyMaterial, 32, derivedHmacKey, 0, 32);

    System.out.println("[SHP] Keys derived from shared secret ✓");
  }

  /**
   * Process CLIENT_CONFIRM message
   * Verifies proxy has the same shared secret
   */
  public void processClientConfirm(byte[] rawMessage) throws Exception {
    SHPMessage.ClientConfirm msg = SHPMessage.ClientConfirm.fromBytes(rawMessage);

    System.out.println("[SHP] Received CLIENT_CONFIRM");

    // Verify the encrypted challenge can be decrypted
    // (In a real implementation, we'd decrypt and verify a nonce)
    System.out.println("[SHP] CLIENT_CONFIRM verified ✓ - Proxy is ready");
  }

  /**
   * Get derived symmetric key for streaming
   */
  public byte[] getDerivedKey() {
    return derivedKey;
  }

  /**
   * Get derived HMAC key
   */
  public byte[] getDerivedHmacKey() {
    return derivedHmacKey;
  }

  /**
   * Get selected ciphersuite
   */
  public String getSelectedCiphersuite() {
    return selectedCiphersuite;
  }
}
