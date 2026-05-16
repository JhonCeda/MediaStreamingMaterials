/* hjUDPproxy, 20/Mar/18
 *
 * This is a very simple (transparent) UDP proxy
 * The proxy can listening on a remote source (server) UDP sender
 * and transparently forward received datagram packets in the
 * delivering endpoint
 *
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *  
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.MulticastSocket;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class hjUDPproxy {
    static class RtsspCryptoContext {
        String cipherAlgorithm;
        String hmacAlgorithm;
        int keySize;
        int ivSize;
        byte[] cipherKey;
        byte[] hmacKey;

        static RtsspCryptoContext fromServerConfig(Properties serverProps) throws Exception {
            RtsspCryptoContext context = new RtsspCryptoContext();
            context.cipherAlgorithm = serverProps.getProperty("cipher.algorithm", "AES/CTR/NoPadding");
            context.hmacAlgorithm = serverProps.getProperty("hmac.algorithm", "HmacSHA256");
            context.keySize = Integer.parseInt(serverProps.getProperty("cipher.keysize", "256"));
            context.ivSize = Integer.parseInt(serverProps.getProperty("cipher.ivsize", "128"));
            String sharedSecret = serverProps.getProperty("rtssp.shared.secret", "RTSSP-default-shared-secret");

            int keyBytes = context.keySize / 8;
            int ivBytes = context.ivSize / 8;
            String info = "RTSSP-Static-Keys|" + context.cipherAlgorithm + "|" + context.keySize + "|" + context.ivSize;
            byte[] keyMaterial = CryptoUtils.hkdf(
                    sharedSecret.getBytes(StandardCharsets.UTF_8),
                    null,
                    info.getBytes(StandardCharsets.UTF_8),
                    keyBytes + 32 + ivBytes);

            context.cipherKey = Arrays.copyOfRange(keyMaterial, 0, keyBytes);
            context.hmacKey = Arrays.copyOfRange(keyMaterial, keyBytes, keyBytes + 32);
            return context;
        }

        byte[] decryptAndVerify(byte[] encryptedWithMac) throws Exception {
            int hmacLength = 32;
            int ivLength = ivSize / 8;

            if (encryptedWithMac.length < ivLength + hmacLength) {
                throw new Exception("[PROXY] Packet too short! Need at least IV + HMAC");
            }

            byte[] iv = Arrays.copyOfRange(encryptedWithMac, 0, ivLength);
            int encryptedLength = encryptedWithMac.length - ivLength - hmacLength;
            byte[] encryptedPayload = Arrays.copyOfRange(encryptedWithMac, ivLength, ivLength + encryptedLength);
            byte[] receivedHmac = Arrays.copyOfRange(encryptedWithMac, ivLength + encryptedLength, encryptedWithMac.length);

            Mac hmacVerify = Mac.getInstance(hmacAlgorithm);
            hmacVerify.init(new SecretKeySpec(hmacKey, 0, hmacKey.length, hmacAlgorithm));
            byte[] computedHmac = hmacVerify.doFinal(encryptedPayload);
            if (!MessageDigest.isEqual(computedHmac, receivedHmac)) {
                throw new Exception("[PROXY] HMAC verification failed! Packet may be corrupted or tampered.");
            }

            Cipher decipher = Cipher.getInstance(cipherAlgorithm);
            SecretKeySpec keySpec = new SecretKeySpec(cipherKey, 0, cipherKey.length, "AES");
            if (cipherAlgorithm.contains("GCM")) {
                decipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
            } else {
                decipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
            }

            return decipher.doFinal(encryptedPayload);
        }
    }

    public static void main(String[] args) throws Exception {
        // Load mode from server config
        String mode = "RTSSP"; // default
        String movieName = "movies/cars.dat"; // default
        Properties serverProps = new Properties();

        try {
            String serverConfig = "../hjStreamServer/Cryptoconfig.conf";
            if (Files.exists(Paths.get(serverConfig))) {
                serverProps.load(new FileInputStream(serverConfig));
                mode = serverProps.getProperty("mode", "RTSSP");
            }
        } catch (Exception e) {
            System.out.println("[PROXY] Could not read server config, defaulting to RTSSP");
        }

        // Get movie name from command line argument or use default
        if (args.length > 0) {
            movieName = args[0];
        }

        System.out.println("[PROXY] Mode: " + mode);
        System.out.println("[PROXY] Movie: " + movieName);

        // If RTSSP-SHP mode, perform handshake first
        SHPClient shpClient = null;
        if ("RTSSP-SHP".equalsIgnoreCase(mode)) {
            shpClient = performHandshake(movieName);
        }

        RtsspCryptoContext rtsspCrypto = null;
        if ("RTSSP".equalsIgnoreCase(mode)) {
            rtsspCrypto = RtsspCryptoContext.fromServerConfig(serverProps);
            System.out.println("[PROXY] RTSSP static crypto initialized: " + rtsspCrypto.cipherAlgorithm);
        }

        // Then proceed with UDP forwarding, passing the SHPClient for decryption
        performForwarding(shpClient, rtsspCrypto);
    }

    static SHPClient performHandshake(String movieName) throws Exception {
        System.out.println("[PROXY] Performing SHP handshake...");

        // Initialize SHPClient with proxy credentials
        SHPClient shpClient = new SHPClient(
                "proxy.jks", // keystore path
                "proxypass", // keystore password
                "proxy.truststore", // truststore path
                "proxypass", // truststore password
                "proxy", // key alias
                "proxypass" // key password
        );

        String[] ciphersuites = { "AES/CTR/NoPadding", "AES/GCM/NoPadding" };

        try {
            shpClient.performHandshake("localhost", 8888, movieName, ciphersuites);

            System.out.println("[PROXY] Handshake successful!");
            System.out.println("[PROXY] Derived cipher key: " + shpClient.getDerivedKey().length + " bytes");
            System.out.println("[PROXY] Derived HMAC key: " + shpClient.getDerivedHmacKey().length + " bytes");
            System.out.println("[PROXY] Selected ciphersuite: " + shpClient.getSelectedCiphersuite());

            return shpClient;

        } catch (Exception e) {
            System.err.println("[PROXY] Handshake failed: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    static void performForwarding(SHPClient shpClient, RtsspCryptoContext rtsspCrypto) throws Exception {
        InputStream inputStream = new FileInputStream("config.properties");
        if (inputStream == null) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        Properties properties = new Properties();
        properties.load(inputStream);
        String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s))
                .collect(Collectors.toSet());

        // Create input socket with SO_REUSEADDR to avoid "Address already in use"
        // errors
        DatagramSocket inSocket = new DatagramSocket(null);
        inSocket.setReuseAddress(true);
        inSocket.bind(inSocketAddress);

        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[16384]; // Increased from 4096 to accommodate IV + encrypted data + HMAC

        System.out.println("[PROXY] Listening on " + inSocketAddress);
        System.out.println("[PROXY] Forwarding to: " + outSocketAddressSet);
        System.out.println("[PROXY] Ready to receive packets...");

        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket);

            // Extract RTSSP Header (first 4 bytes)
            byte version = buffer[0];
            byte type = buffer[1];
            int payloadSize = ((buffer[2] & 0xFF) << 8) | (buffer[3] & 0xFF);

            // Skip control messages (START=0x00, FINISH=0x02), only process DATA frames
            // (0x01)
            if (type != 0x01) {
                // Skip control frames
                continue;
            }

            // Extract Encrypted Payload with IV + HMAC (skip first 4 bytes of header)
            byte[] encryptedWithMac = Arrays.copyOfRange(buffer, 4, inPacket.getLength());

            // DECRYPT AND VERIFY if we have SHP keys
            byte[] clearVideoFrame;
            if (shpClient != null) {
                clearVideoFrame = shpClient.decryptAndVerify(encryptedWithMac);
            } else if (rtsspCrypto != null) {
                clearVideoFrame = rtsspCrypto.decryptAndVerify(encryptedWithMac);
            } else {
                // Fallback for legacy clear streams.
                clearVideoFrame = encryptedWithMac;
            }

            System.out.print(".");

            // FORWARD ONLY THE CLEAR DATA to the media player
            for (SocketAddress outSocketAddress : outSocketAddressSet) {
                outSocket.send(new DatagramPacket(clearVideoFrame, clearVideoFrame.length, outSocketAddress));
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
