import java.io.*;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;

/**
 * SHPMessage - Handshake message classes for SHP protocol
 * 
 * Message format (serialized):
 * [messageType:1][payloadLength:4][payload...]
 */
public class SHPMessage {

  public static final byte CLIENT_HELLO = 0x10;
  public static final byte SERVER_HELLO = 0x11;
  public static final byte CLIENT_CONFIRM = 0x12;

  /**
   * Serialize a byte length-prefixed field
   */
  private static void writeByteArray(ByteBuffer bb, byte[] data) {
    bb.putInt(data.length);
    bb.put(data);
  }

  /**
   * Deserialize a byte length-prefixed field
   */
  private static byte[] readByteArray(ByteBuffer bb) {
    int len = bb.getInt();
    byte[] data = new byte[len];
    bb.get(data);
    return data;
  }

  /**
   * CLIENT HELLO message
   * Sent by Proxy to Server to initiate handshake
   */
  public static class ClientHello {
    public String movieName;
    public byte[] certificate; // DER-encoded X509 certificate
    public byte[] ecdhPublicKey; // DER-encoded public key
    public String[] ciphersuites; // e.g., ["AES/CTR/NoPadding", "ChaCha20"]
    public byte[] nonce; // Random 16 bytes
    public byte[] signature; // ECDSA signature of (movieName + cert + ecdhPubKey + ciphersuites + nonce)

    public ClientHello() {
    }

    public ClientHello(String movieName, byte[] cert, byte[] ecdhPubKey, String[] ciphers, byte[] nonce) {
      this.movieName = movieName;
      this.certificate = cert;
      this.ecdhPublicKey = ecdhPubKey;
      this.ciphersuites = ciphers;
      this.nonce = nonce;
    }

    /**
     * Get data to be signed (before adding signature)
     */
    public byte[] getDataToSign() throws Exception {
      ByteBuffer bb = ByteBuffer.allocate(1024);
      bb.putInt(movieName.length());
      bb.put(movieName.getBytes("UTF-8"));
      writeByteArray(bb, certificate);
      writeByteArray(bb, ecdhPublicKey);
      bb.putInt(ciphersuites.length);
      for (String cs : ciphersuites) {
        byte[] csBytes = cs.getBytes("UTF-8");
        bb.putInt(csBytes.length);
        bb.put(csBytes);
      }
      writeByteArray(bb, nonce);
      bb.flip();
      byte[] result = new byte[bb.remaining()];
      bb.get(result);
      return result;
    }

    /**
     * Serialize CLIENT_HELLO to bytes
     */
    public byte[] toBytes() throws Exception {
      ByteBuffer bb = ByteBuffer.allocate(4096);
      bb.put(CLIENT_HELLO);
      bb.putInt(movieName.length());
      bb.put(movieName.getBytes("UTF-8"));
      writeByteArray(bb, certificate);
      writeByteArray(bb, ecdhPublicKey);
      bb.putInt(ciphersuites.length);
      for (String cs : ciphersuites) {
        byte[] csBytes = cs.getBytes("UTF-8");
        bb.putInt(csBytes.length);
        bb.put(csBytes);
      }
      writeByteArray(bb, nonce);
      writeByteArray(bb, signature);
      bb.flip();
      byte[] result = new byte[bb.remaining()];
      bb.get(result);
      return result;
    }

    /**
     * Deserialize CLIENT_HELLO from bytes
     */
    public static ClientHello fromBytes(byte[] data) throws Exception {
      ByteBuffer bb = ByteBuffer.wrap(data);
      if (bb.get() != CLIENT_HELLO)
        throw new Exception("Invalid message type");

      ClientHello msg = new ClientHello();
      int movieLen = bb.getInt();
      byte[] movieBytes = new byte[movieLen];
      bb.get(movieBytes);
      msg.movieName = new String(movieBytes, "UTF-8");
      msg.certificate = readByteArray(bb);
      msg.ecdhPublicKey = readByteArray(bb);
      int csLen = bb.getInt();
      msg.ciphersuites = new String[csLen];
      for (int i = 0; i < csLen; i++) {
        int csStrLen = bb.getInt();
        byte[] csBytes = new byte[csStrLen];
        bb.get(csBytes);
        msg.ciphersuites[i] = new String(csBytes, "UTF-8");
      }
      msg.nonce = readByteArray(bb);
      msg.signature = readByteArray(bb);
      return msg;
    }
  }

  /**
   * SERVER HELLO message
   * Sent by Server in response to CLIENT_HELLO
   */
  public static class ServerHello {
    public boolean movieFound; // true if movie exists
    public byte[] certificate; // DER-encoded X509 certificate
    public byte[] ecdhPublicKey; // DER-encoded public key
    public String selectedCiphersuite; // Selected from client's list
    public byte[] clientNonce; // Echo back client's nonce
    public byte[] serverNonce; // Server's own nonce
    public byte[] signature; // ECDSA signature

    public ServerHello() {
    }

    public ServerHello(boolean found, byte[] cert, byte[] ecdhPubKey, String cipher, byte[] cNonce,
        byte[] sNonce) {
      this.movieFound = found;
      this.certificate = cert;
      this.ecdhPublicKey = ecdhPubKey;
      this.selectedCiphersuite = cipher;
      this.clientNonce = cNonce;
      this.serverNonce = sNonce;
    }

    /**
     * Get data to be signed
     */
    public byte[] getDataToSign() throws Exception {
      ByteBuffer bb = ByteBuffer.allocate(1024);
      bb.put((byte) (movieFound ? 1 : 0));
      writeByteArray(bb, certificate);
      writeByteArray(bb, ecdhPublicKey);
      byte[] csBytes = selectedCiphersuite.getBytes("UTF-8");
      bb.putInt(csBytes.length);
      bb.put(csBytes);
      writeByteArray(bb, clientNonce);
      writeByteArray(bb, serverNonce);
      bb.flip();
      byte[] result = new byte[bb.remaining()];
      bb.get(result);
      return result;
    }

    /**
     * Serialize SERVER_HELLO to bytes
     */
    public byte[] toBytes() throws Exception {
      ByteBuffer bb = ByteBuffer.allocate(4096);
      bb.put(SERVER_HELLO);
      bb.put((byte) (movieFound ? 1 : 0));
      writeByteArray(bb, certificate);
      writeByteArray(bb, ecdhPublicKey);
      byte[] csBytes = selectedCiphersuite.getBytes("UTF-8");
      bb.putInt(csBytes.length);
      bb.put(csBytes);
      writeByteArray(bb, clientNonce);
      writeByteArray(bb, serverNonce);
      writeByteArray(bb, signature);
      bb.flip();
      byte[] result = new byte[bb.remaining()];
      bb.get(result);
      return result;
    }

    /**
     * Deserialize SERVER_HELLO from bytes
     */
    public static ServerHello fromBytes(byte[] data) throws Exception {
      ByteBuffer bb = ByteBuffer.wrap(data);
      if (bb.get() != SERVER_HELLO)
        throw new Exception("Invalid message type");

      ServerHello msg = new ServerHello();
      msg.movieFound = bb.get() == 1;
      msg.certificate = readByteArray(bb);
      msg.ecdhPublicKey = readByteArray(bb);
      int csLen = bb.getInt();
      byte[] csBytes = new byte[csLen];
      bb.get(csBytes);
      msg.selectedCiphersuite = new String(csBytes, "UTF-8");
      msg.clientNonce = readByteArray(bb);
      msg.serverNonce = readByteArray(bb);
      msg.signature = readByteArray(bb);
      return msg;
    }
  }

  /**
   * CLIENT CONFIRM message
   * Proves Proxy has derived the same shared secret
   */
  public static class ClientConfirm {
    public byte[] encryptedChallenge; // Challenge response (nonce encrypted with derived key)
    public byte[] signature; // ECDSA signature of encrypted challenge

    public ClientConfirm() {
    }

    public ClientConfirm(byte[] encrypted) {
      this.encryptedChallenge = encrypted;
    }

    /**
     * Serialize CLIENT_CONFIRM to bytes
     */
    public byte[] toBytes() throws Exception {
      ByteBuffer bb = ByteBuffer.allocate(2048);
      bb.put(CLIENT_CONFIRM);
      writeByteArray(bb, encryptedChallenge);
      writeByteArray(bb, signature);
      bb.flip();
      byte[] result = new byte[bb.remaining()];
      bb.get(result);
      return result;
    }

    /**
     * Deserialize CLIENT_CONFIRM from bytes
     */
    public static ClientConfirm fromBytes(byte[] data) throws Exception {
      ByteBuffer bb = ByteBuffer.wrap(data);
      if (bb.get() != CLIENT_CONFIRM)
        throw new Exception("Invalid message type");

      ClientConfirm msg = new ClientConfirm();
      msg.encryptedChallenge = readByteArray(bb);
      msg.signature = readByteArray(bb);
      return msg;
    }
  }
}
