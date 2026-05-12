/*
* hjStreamServer.java 
* Streaming server: streams video frames in UDP packets
* for clients to play in real time the transmitted movies
* 
* Part 1: RTSSP - Real-Time Secure Streaming Protocol
* - Generates random keys and IVs per session
* - Encrypts frames with configurable cipher
* - Adds HMAC for integrity
* - Sends START and FINISH control messages
*/

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;

class hjStreamServer {

	private static final byte START_FRAME = 0x00;
	private static final byte DATA_FRAME = 0x01;
	private static final byte FINISH_FRAME = 0x02;

	static class CryptoConfig {
		String mode; // RTSSP or RTSSP-SHP
		String cipherAlgorithm;
		String hmacAlgorithm;
		int keySize; // in bits
		int ivSize; // in bits

		// Part 2 settings
		String serverKeystorePath;
		String serverKeystorePassword;
		String serverKeystoreAlias;
		String serverKeystoreKeypass;
		String serverTrustStorePath;
		String serverTrustStorePassword;
		String handshakeProxyHost;
		int handshakeProxyPort;
	}

	static CryptoConfig loadCryptoConfig(String configFile) throws Exception {
		Properties props = new Properties();
		props.load(new FileInputStream(configFile));

		CryptoConfig config = new CryptoConfig();
		config.mode = props.getProperty("mode", "RTSSP");
		config.cipherAlgorithm = props.getProperty("cipher.algorithm", "AES/CTR/NoPadding");
		config.hmacAlgorithm = props.getProperty("hmac.algorithm", "HmacSHA256");
		config.keySize = Integer.parseInt(props.getProperty("cipher.keysize", "256"));
		config.ivSize = Integer.parseInt(props.getProperty("cipher.ivsize", "128"));
		// Load Part 2 (SHP) settings
		config.serverKeystorePath = props.getProperty("server.keystore.path", "server.jks");
		config.serverKeystorePassword = props.getProperty("server.keystore.password", "serverpass");
		config.serverKeystoreAlias = props.getProperty("server.keystore.alias", "server");
		config.serverKeystoreKeypass = props.getProperty("server.keystore.keypass", "serverpass");
		config.serverTrustStorePath = props.getProperty("server.truststore.path", "server.truststore");
		config.serverTrustStorePassword = props.getProperty("server.truststore.password", "serverpass");
		config.handshakeProxyHost = props.getProperty("handshake.proxy.host", "localhost");
		config.handshakeProxyPort = Integer.parseInt(props.getProperty("handshake.proxy.port", "9999"));
		return config;
	}

	static byte[] generateRandomBytes(int sizeBits) {
		SecureRandom random = new SecureRandom();
		byte[] bytes = new byte[sizeBits / 8];
		random.nextBytes(bytes);
		return bytes;
	}

	static void sendControlMessage(DatagramSocket socket, InetSocketAddress addr, byte type, byte[] data)
			throws Exception {
		ByteBuffer buffer = ByteBuffer.allocate(4 + (data != null ? data.length : 0));
		buffer.put((byte) 1); // version
		buffer.put(type); // type (0x00=START, 0x01=DATA, 0x02=FINISH)
		buffer.putShort((short) (data != null ? data.length : 0)); // length
		if (data != null) {
			buffer.put(data);
		}

		byte[] packet = buffer.array();
		DatagramPacket p = new DatagramPacket(packet, packet.length, addr);
		socket.send(p);
	}

	static byte[] encryptAndMac(byte[] data, int offset, int length, Cipher cipher, Mac mac,
			String cipherAlgorithm, SecretKeySpec keySpec, byte[] baseIV,
			int frameCounter) throws Exception {

		// For GCM, we need to reinitialize with a unique IV for each frame
		if (cipherAlgorithm.contains("GCM")) {
			// Generate unique IV by XORing frame counter into the base IV
			byte[] uniqueIV = baseIV.clone();
			ByteBuffer counterBytes = ByteBuffer.allocate(4);
			counterBytes.putInt(frameCounter);
			// XOR the last 4 bytes of IV with the frame counter
			for (int i = 0; i < 4; i++) {
				uniqueIV[uniqueIV.length - 4 + i] ^= counterBytes.array()[i];
			}

			GCMParameterSpec gcmSpec = new GCMParameterSpec(128, uniqueIV);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
		}

		byte[] encrypted = cipher.doFinal(data, offset, length);
		byte[] hmac = mac.doFinal(encrypted);

		// PREPEND IV to the packet so proxy can extract and use it for decryption
		ByteBuffer buffer = ByteBuffer.allocate(baseIV.length + encrypted.length + hmac.length);
		buffer.put(baseIV); // IV goes first
		buffer.put(encrypted);
		buffer.put(hmac);
		return buffer.array();
	}

	static public void main(String[] args) throws Exception {
		if (args.length != 3) {
			System.out.println("Error, use: mySend <movie> <ip-multicast-address> <port>");
			System.out.println("        or: mySend <movie> <ip-unicast-address> <port>");
			System.exit(-1);
		}

		// Load crypto configuration
		CryptoConfig cryptoConfig = loadCryptoConfig("Cryptoconfig.conf");
		System.out.println("[RTSSP] Mode: " + cryptoConfig.mode);
		System.out.println("[RTSSP] Algorithms: " + cryptoConfig.cipherAlgorithm + " | " + cryptoConfig.hmacAlgorithm);

		// Validate mode
		if (!cryptoConfig.mode.equals("RTSSP") && !cryptoConfig.mode.equals("RTSSP-SHP")) {
			System.err.println("[ERROR] Invalid mode: " + cryptoConfig.mode + ". Must be RTSSP or RTSSP-SHP");
			System.exit(-1);
		}

		byte[] sessionKey;
		byte[] sessionIV;
		byte[] hmacKey;
		String actualCiphersuite = cryptoConfig.cipherAlgorithm;
		SHPHandshake shpHandshake = null;

		if (cryptoConfig.mode.equals("RTSSP")) {
			// Part 1: Generate random keys
			sessionKey = generateRandomBytes(cryptoConfig.keySize);
			sessionIV = generateRandomBytes(cryptoConfig.ivSize);
			hmacKey = generateRandomBytes(cryptoConfig.keySize);

			System.out.println("[RTSSP] Generated random key (" + cryptoConfig.keySize + " bits)");
			System.out.println("[RTSSP] Generated random IV (" + cryptoConfig.ivSize + " bits)");
			System.out.println("[RTSSP] Running Part 1: RTSSP (Static session keys)");
		} else {
			// Part 2: SHP Handshake
			System.out.println("[SHP] Initializing handshake...");
			shpHandshake = new SHPHandshake(
					cryptoConfig.serverKeystorePath, cryptoConfig.serverKeystorePassword,
					cryptoConfig.serverTrustStorePath, cryptoConfig.serverTrustStorePassword,
					cryptoConfig.serverKeystoreAlias, cryptoConfig.serverKeystoreKeypass);

			// Wait for CLIENT_HELLO from proxy on TCP port
			ServerSocket handshakeServer = new ServerSocket(cryptoConfig.handshakeProxyPort);
			System.out.println("[SHP] Waiting for handshake on port " + cryptoConfig.handshakeProxyPort + "...");

			Socket proxySocket = handshakeServer.accept();
			InputStream in = proxySocket.getInputStream();
			OutputStream out = proxySocket.getOutputStream();

			// Receive CLIENT_HELLO
			byte[] clientHelloData = new byte[4096];
			int bytesRead = in.read(clientHelloData);
			if (bytesRead < 0) {
				throw new Exception("[SHP] Connection closed before CLIENT_HELLO received!");
			}
			System.out.println("[SHP] Received CLIENT_HELLO (" + bytesRead + " bytes)");
			SHPMessage.ClientHello clientHello = shpHandshake.processClientHello(
					java.util.Arrays.copyOf(clientHelloData, bytesRead));

			if (!clientHello.movieName.equals(args[0])) {
				System.err.println("[SHP] Movie name mismatch! Expected: " + args[0] + ", got: " + clientHello.movieName);
				proxySocket.close();
				handshakeServer.close();
				System.exit(-1);
			}

			// Derive shared secret from proxy's ECDH public key
			shpHandshake.deriveSharedSecret(clientHello.ecdhPublicKey);

			// Send SERVER_HELLO
			SHPMessage.ServerHello serverHello = shpHandshake.createServerHello(
					args[0], true, clientHello.ciphersuites, clientHello.nonce);
			out.write(serverHello.toBytes());
			out.flush();

			// Receive CLIENT_CONFIRM
			byte[] clientConfirmData = new byte[2048];
			bytesRead = in.read(clientConfirmData);
			shpHandshake.processClientConfirm(java.util.Arrays.copyOf(clientConfirmData, bytesRead));

			// Get derived keys
			sessionKey = shpHandshake.getDerivedKey();
			hmacKey = shpHandshake.getDerivedHmacKey();
			sessionIV = generateRandomBytes(cryptoConfig.ivSize); // New IV per stream
			actualCiphersuite = shpHandshake.getSelectedCiphersuite();

			proxySocket.close();
			handshakeServer.close();

			System.out.println("[SHP] Handshake complete! Ready to stream.");
			System.out.println("[RTSSP] Running Part 2: RTSSP-SHP (Negotiated keys)");
		}

		// Initialize cipher and mac
		Cipher cipher = Cipher.getInstance(actualCiphersuite);
		Mac mac = Mac.getInstance(cryptoConfig.hmacAlgorithm);

		SecretKeySpec keySpec = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");
		SecretKeySpec hmacKeySpec = new SecretKeySpec(hmacKey, 0, hmacKey.length, cryptoConfig.hmacAlgorithm);

		// Handle different cipher modes
		if (actualCiphersuite.contains("GCM")) {
			// GCM requires GCMParameterSpec with tag length 128 bits
			GCMParameterSpec gcmSpec = new GCMParameterSpec(128, sessionIV);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
		} else {
			// CTR and other modes use IvParameterSpec
			IvParameterSpec ivSpec = new IvParameterSpec(sessionIV);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
		}
		mac.init(hmacKeySpec);

		int size;
		int csize = 0;
		int count = 0;
		long time;
		DataInputStream g = new DataInputStream(new FileInputStream(args[0]));
		byte[] buff = new byte[16384]; // Increased from 4096 to accommodate IV + encrypted data + HMAC

		DatagramSocket s = new DatagramSocket();
		InetSocketAddress addr = new InetSocketAddress(args[1], Integer.parseInt(args[2]));
		DatagramPacket p = new DatagramPacket(buff, buff.length, addr);
		long t0 = System.nanoTime(); // Ref. time
		long q0 = 0;

		// Send START control message
		sendControlMessage(s, addr, START_FRAME, null);
		System.out.println("[RTSSP] START message sent");

		// Movies are encoded in .dat files, where each
		// frame is encoded in a real-time sequence of MP4 frames
		// Somewhat an FFMPEG4 playing scheme .. Dont worry

		// Each frame has:
		// Short size || Long Timestamp || byte[] EncodedMP4Frame
		// You can read (frame by frame to transmit ...
		// But you must folow the "real-time" encoding conditions

		// OK let's do it !

		while (g.available() > 0) {

			size = g.readShort(); // size of the frame
			csize = csize + size;
			time = g.readLong(); // timestamp of the frame
			if (count == 0)
				q0 = time; // ref. time in the stream
			count += 1;
			g.readFully(buff, 0, size);

			// Encrypt frame and calculate HMAC
			byte[] encryptedPayload = encryptAndMac(buff, 0, size, cipher, mac, actualCiphersuite, keySpec, sessionIV, count);

			// Build RTSSP packet: [version(1)|type(1)|length(2)|encrypted_frame|hmac]
			ByteBuffer packetBuffer = ByteBuffer.allocate(4 + encryptedPayload.length);
			packetBuffer.put((byte) 1); // version
			packetBuffer.put(DATA_FRAME); // type = DATA
			packetBuffer.putShort((short) encryptedPayload.length); // length
			packetBuffer.put(encryptedPayload);

			byte[] rtsspPacket = packetBuffer.array();
			p.setData(rtsspPacket, 0, rtsspPacket.length);
			p.setSocketAddress(addr);

			long t = System.nanoTime(); // what time is it?

			// Decision about the right time to transmit
			Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));

			// send datagram (udp packet) w/ encrypted payload + HMAC
			s.send(p);

			// Just for awareness ... (debug)
			System.out.print(":");
		}

		// Send FINISH control message
		sendControlMessage(s, addr, FINISH_FRAME, null);
		System.out.println("[RTSSP] FINISH message sent");

		long tend = System.nanoTime(); // "The end" time
		System.out.println();
		System.out.println("[RTSSP] DONE! all frames sent: " + count);

		long duration = (tend - t0) / 1000000000;
		System.out.println("[RTSSP] Movie duration " + duration + " s");
		if (duration > 0) {
			System.out.println("[RTSSP] Throughput " + count / duration + " fps");
			System.out.println("[RTSSP] Throughput " + (8 * (csize) / duration) / 1000 + " Kbps");
		}

	}
}
