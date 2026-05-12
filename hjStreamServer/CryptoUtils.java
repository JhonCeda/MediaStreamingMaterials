import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * CryptoUtils - Cryptographic utilities for SHP handshake
 * Handles ECDH key agreement, KDF, and ECDSA signatures
 */
public class CryptoUtils {

  /**
   * Generate ECDH keypair on secp256r1 curve
   */
  public static KeyPair generateECDHKeyPair() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
    kpg.initialize(spec);
    return kpg.generateKeyPair();
  }

  /**
   * Perform ECDH key agreement to derive shared secret
   * 
   * @param privateKey Own private key
   * @param publicKey  Peer's public key
   * @return Shared secret (32 bytes)
   */
  public static byte[] performECDH(PrivateKey privateKey, PublicKey publicKey) throws Exception {
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    ka.init(privateKey);
    ka.doPhase(publicKey, true);
    byte[] sharedSecret = ka.generateSecret();

    // Truncate to 32 bytes if longer (shouldn't be for secp256r1)
    if (sharedSecret.length > 32) {
      return Arrays.copyOf(sharedSecret, 32);
    }
    return sharedSecret;
  }

  /**
   * HKDF-SHA256: Key Derivation Function
   * Derives symmetric key from shared secret
   * 
   * @param sharedSecret The ECDH shared secret
   * @param salt         Optional salt (can be all zeros)
   * @param info         Optional info string for domain separation
   * @param keyLen       Desired key length in bytes
   * @return Derived key material
   */
  public static byte[] hkdf(byte[] sharedSecret, byte[] salt, byte[] info, int keyLen) throws Exception {
    if (salt == null || salt.length == 0) {
      salt = new byte[32]; // All zeros
    }

    // HKDF-Extract
    Mac hmac = Mac.getInstance("HmacSHA256");
    hmac.init(new SecretKeySpec(salt, 0, salt.length, "HmacSHA256"));
    byte[] prk = hmac.doFinal(sharedSecret);

    // HKDF-Expand
    byte[] result = new byte[keyLen];
    byte[] t = new byte[0];
    byte[] ti;
    int iterations = (int) Math.ceil((double) keyLen / 32); // SHA256 produces 32 bytes

    hmac.reset();
    hmac.init(new SecretKeySpec(prk, 0, prk.length, "HmacSHA256"));

    for (int i = 1; i <= iterations; i++) {
      hmac.update(t);
      if (info != null) {
        hmac.update(info);
      }
      hmac.update((byte) i);
      ti = hmac.doFinal();

      int length = Math.min(ti.length, keyLen - (i - 1) * 32);
      System.arraycopy(ti, 0, result, (i - 1) * 32, length);

      t = ti;
      hmac.reset();
      hmac.init(new SecretKeySpec(prk, 0, prk.length, "HmacSHA256"));
    }

    return result;
  }

  /**
   * Sign data with ECDSA
   * 
   * @param data       Data to sign
   * @param privateKey Private key for signing
   * @return Signature bytes
   */
  public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
    Signature sig = Signature.getInstance("SHA256withRSA");
    sig.initSign(privateKey);
    sig.update(data);
    return sig.sign();
  }

  /**
   * Verify ECDSA signature
   * 
   * @param data      Original data
   * @param signature Signature bytes
   * @param publicKey Public key for verification
   * @return true if signature is valid
   */
  public static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
    Signature sig = Signature.getInstance("SHA256withRSA");
    sig.initVerify(publicKey);
    sig.update(data);
    return sig.verify(signature);
  }

  /**
   * Generate random nonce
   */
  public static byte[] generateNonce(int sizeBytes) {
    SecureRandom random = new SecureRandom();
    byte[] nonce = new byte[sizeBytes];
    random.nextBytes(nonce);
    return nonce;
  }

  /**
   * Convert bytes to hex string (for debugging)
   */
  public static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  /**
   * Convert hex string to bytes
   */
  public static byte[] hexToBytes(String hex) {
    int len = hex.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
          + Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
  }
}
