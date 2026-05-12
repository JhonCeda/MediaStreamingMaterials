import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * SHPClient - Client-side SHP handshake for proxy
 * Initiates handshake with server to negotiate encryption keys
 */
public class SHPClient {

  private KeyStore keyStore;
  private KeyStore trustStore;
  private String keyAlias;
  private String keyPassword;
  private PrivateKey proxyPrivateKey;
  private java.security.cert.Certificate proxyCertificate;

  // Handshake state
  private KeyPair proxyECDHPair;
  private byte[] sharedSecret;
  private byte[] derivedKey;
  private byte[] derivedHmacKey;
  private String selectedCiphersuite;

  /**
   * Initialize client with proxy credentials
   */
  public SHPClient(String keystorePath, String keystorePassword, String trustStorePath,
      String trustStorePassword, String keyAlias, String keyPassword) throws Exception {
    this.keyAlias = keyAlias;
    this.keyPassword = keyPassword;

    // Load keystore
    keyStore = KeyStore.getInstance("JKS");
    keyStore.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());
    proxyPrivateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());
    proxyCertificate = keyStore.getCertificate(keyAlias);

    // Load truststore
    trustStore = KeyStore.getInstance("JKS");
    trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());

    // Generate proxy's ECDH keypair
    proxyECDHPair = CryptoUtils.generateECDHKeyPair();

    System.out.println("[SHP-Client] Proxy handshake initialized");
  }

  /**
   * Get proxy's ECDH public key in DER format
   */
  public byte[] getECDHPublicKeyDER() throws Exception {
    PublicKey pubKey = proxyECDHPair.getPublic();
    return pubKey.getEncoded();
  }

  /**
   * Get proxy's certificate in DER format
   */
  public byte[] getCertificateDER() throws Exception {
    return proxyCertificate.getEncoded();
  }

  /**
   * Initiate handshake: send CLIENT_HELLO
   * Encrypts movieName for handshake confidentiality
   */
  public void performHandshake(String serverHost, int serverPort, String movieName, String[] ciphersuites)
      throws Exception {
    System.out.println("[SHP-Client] Connecting to server at " + serverHost + ":" + serverPort);

    Socket socket = new Socket(serverHost, serverPort);
    InputStream in = socket.getInputStream();
    OutputStream out = socket.getOutputStream();

    // Load server's certificate to get public key for encryption
    java.security.cert.Certificate serverCert = trustStore.getCertificate("server");
    if (serverCert == null) {
      throw new Exception("[SHP-Client] Server certificate not found in truststore!");
    }
    PublicKey serverPublicKey = serverCert.getPublicKey();
    System.out.println("[SHP-Client] Loaded server public key for encryption");

    // Step 1: Send CLIENT_HELLO
    byte[] clientNonce = CryptoUtils.generateNonce(16);
    SHPMessage.ClientHello clientHello = new SHPMessage.ClientHello(
        movieName, getCertificateDER(), getECDHPublicKeyDER(), ciphersuites, clientNonce);

    // Encrypt movieName with server's public key
    byte[] movieNameBytes = movieName.getBytes("UTF-8");
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
    clientHello.encryptedMovieName = rsaCipher.doFinal(movieNameBytes);
    System.out.println("[SHP-Client] Encrypted movieName (" + movieNameBytes.length + " → "
        + clientHello.encryptedMovieName.length + " bytes)");

    // Sign CLIENT_HELLO (signature now covers encrypted movieName)
    byte[] dataToSign = clientHello.getDataToSign();
    clientHello.signature = CryptoUtils.signData(dataToSign, proxyPrivateKey);

    out.write(clientHello.toBytes());
    out.flush();
    System.out.println("[SHP-Client] CLIENT_HELLO sent ✓ (movieName encrypted)");

    // Step 2: Receive SERVER_HELLO
    byte[] serverHelloData = new byte[4096];
    int bytesRead = in.read(serverHelloData);
    SHPMessage.ServerHello serverHello = SHPMessage.ServerHello
        .fromBytes(java.util.Arrays.copyOf(serverHelloData, bytesRead));

    System.out.println("[SHP-Client] SERVER_HELLO received");

    // Verify server's certificate
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    java.security.cert.Certificate serverCert2 = cf.generateCertificate(
        new ByteArrayInputStream(serverHello.certificate));

    // Verify server's signature
    PublicKey serverPublicKey2 = serverCert2.getPublicKey();
    byte[] serverDataToVerify = serverHello.getDataToSign();
    if (!CryptoUtils.verifySignature(serverDataToVerify, serverHello.signature, serverPublicKey2)) {
      throw new Exception("[SHP-Client] SERVER_HELLO signature verification failed!");
    }
    System.out.println("[SHP-Client] SERVER_HELLO signature verified ✓");

    // Derive shared secret
    deriveSharedSecret(serverHello.ecdhPublicKey);
    selectedCiphersuite = serverHello.selectedCiphersuite;

    // Step 3: Send CLIENT_CONFIRM
    byte[] encryptedChallenge = new byte[16]; // In real implementation, encrypt nonce
    SHPMessage.ClientConfirm clientConfirm = new SHPMessage.ClientConfirm(encryptedChallenge);
    clientConfirm.signature = CryptoUtils.signData(encryptedChallenge, proxyPrivateKey);

    out.write(clientConfirm.toBytes());
    out.flush();
    System.out.println("[SHP-Client] CLIENT_CONFIRM sent ✓");

    System.out.println("[SHP-Client] Handshake complete! Selected cipher: " + selectedCiphersuite);

    socket.close();
  }

  /**
   * Derive shared secret from server's ECDH public key
   */
  private void deriveSharedSecret(byte[] serverECDHPublicKeyDER) throws Exception {
    // Reconstruct server's public key
    KeyFactory kf = KeyFactory.getInstance("EC");
    X509EncodedKeySpec spec = new X509EncodedKeySpec(serverECDHPublicKeyDER);
    PublicKey serverPublicKey = kf.generatePublic(spec);

    // Perform ECDH
    sharedSecret = CryptoUtils.performECDH(proxyECDHPair.getPrivate(), serverPublicKey);
    System.out.println("[SHP-Client] Shared secret derived");

    // Derive symmetric keys using HKDF
    byte[] keyMaterial = CryptoUtils.hkdf(sharedSecret, null, "RTSSP-SHP-Keys".getBytes(), 64);
    derivedKey = new byte[32];
    derivedHmacKey = new byte[32];
    System.arraycopy(keyMaterial, 0, derivedKey, 0, 32);
    System.arraycopy(keyMaterial, 32, derivedHmacKey, 0, 32);

    System.out.println("[SHP-Client] Keys derived from shared secret ✓");
  }

  /**
   * Get derived symmetric key
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

  /**
   * Decrypt and verify received packet (from server to player)
   * Format: [IV(16) | EncryptedPayload(N) | HMAC(32)]
   */
  public byte[] decryptAndVerify(byte[] encryptedWithMac) throws Exception {
    int hmacLength = 32; // HmacSHA256 produces 32 bytes
    int ivLength = 16; // Standard AES IV length

    if (encryptedWithMac.length < ivLength + hmacLength) {
      throw new Exception("[PROXY] Packet too short! Need at least IV(16) + HMAC(32) = 48 bytes");
    }

    // Extract IV from the beginning
    byte[] iv = new byte[ivLength];
    System.arraycopy(encryptedWithMac, 0, iv, 0, ivLength);

    // Extract encrypted payload and HMAC
    int encryptedLength = encryptedWithMac.length - ivLength - hmacLength;
    byte[] encryptedPayload = new byte[encryptedLength];
    byte[] receivedHmac = new byte[hmacLength];

    System.arraycopy(encryptedWithMac, ivLength, encryptedPayload, 0, encryptedLength);
    System.arraycopy(encryptedWithMac, ivLength + encryptedLength, receivedHmac, 0, hmacLength);

    // VERIFY HMAC (computed over encrypted payload only)
    Mac hmacVerify = Mac.getInstance("HmacSHA256");
    hmacVerify.init(new SecretKeySpec(derivedHmacKey, 0, derivedHmacKey.length, "HmacSHA256"));
    byte[] computedHmac = hmacVerify.doFinal(encryptedPayload);

    boolean hmacValid = MessageDigest.isEqual(computedHmac, receivedHmac);
    if (!hmacValid) {
      throw new Exception("[PROXY] HMAC verification failed! Packet may be corrupted or tampered.");
    }

    // DECRYPT using the negotiated algorithm
    Cipher decipher = Cipher.getInstance(selectedCiphersuite);

    if (selectedCiphersuite.contains("GCM")) {
      // GCM mode requires GCMParameterSpec
      GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
      decipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(derivedKey, 0, derivedKey.length, "AES"), gcmSpec);
    } else {
      // CTR and other modes use IvParameterSpec
      IvParameterSpec ivSpec = new IvParameterSpec(iv);
      decipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(derivedKey, 0, derivedKey.length, "AES"), ivSpec);
    }

    byte[] clearVideoFrame = decipher.doFinal(encryptedPayload);
    return clearVideoFrame;
  }
}
