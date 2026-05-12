# RTSSP & RTSSP-SHP: Real-Time Secure Streaming Protocol

A complete implementation of secure video streaming with two protocol modes:
- **RTSSP**: Real-Time Secure Streaming Protocol (static session keys)
- **RTSSP-SHP**: With Secure Handshake Protocol (ECDH + ECDSA negotiation)

## Overview

This project streams encrypted video frames over UDP with configurable encryption (AES/CTR or AES/GCM) and HMAC-SHA256 integrity verification. The proxy decrypts frames before forwarding to a media player.

```
┌─────────────┐                          ┌─────────────┐                    ┌──────────────┐
│   Server    │──(Encrypted UDP:5000)───▶│    Proxy    │──(Clear UDP:7777)─▶│   Celluloid  │
│ Port 8888   │  [Handshake TCP]         │             │                     │   Player     │
└─────────────┘  (RTSSP-SHP mode)        └─────────────┘                    └──────────────┘
```

## Architecture

### Components

1. **hjStreamServer** - Streaming server
   - Reads video frames from `.dat` files
   - Encrypts frames with AES (CTR or GCM mode)
   - Appends HMAC for integrity
   - Sends UDP packets to proxy on port 5000
   - Optional: Performs ECDH handshake on TCP port 8888 (RTSSP-SHP mode)

2. **hjUDPproxy** - UDP proxy & decryption engine
   - Listens for encrypted frames on UDP port 5000
   - Verifies HMAC integrity
   - Decrypts frames using negotiated keys
   - Forwards clear video to media player on UDP port 7777
   - Optional: Connects to server for handshake (RTSSP-SHP mode)

3. **Media Player** (Celluloid/VLC/MPV)
   - Receives clear UDP stream on port 7777
   - Plays video in real-time

### Packet Format

**From Server to Proxy:**
```
[RTSSP Header]  [IV]        [Encrypted Data]     [HMAC]
 4 bytes        16 bytes     N bytes              32 bytes
```

**From Proxy to Player:**
```
[Clear Video Data]
N bytes (decrypted)
```

## Key Features

### Mode 1: RTSSP (Static Keys)
- Server generates random 256-bit cipher key and HMAC key
- Keys transmitted out-of-band (not shown here, assumed pre-shared)
- Fast startup, no handshake overhead
- Suitable for test environments

### Mode 2: RTSSP-SHP (Secure Handshake)
- **ECDH (Elliptic Curve Diffie-Hellman)**: Negotiate shared secret on secp256r1
- **ECDSA (Elliptic Curve Digital Signature Algorithm)**: Mutual authentication
- **HKDF-SHA256**: Derive symmetric keys from shared secret
- **X.509 Certificates**: Self-signed, stored in JKS keystores
- Keys are ephemeral and unique per stream

### Encryption Options
- **AES/CTR/NoPadding**: Counter mode (stream cipher)
  - Fast, no padding overhead
  - Unique IV per frame prevents reuse
  - Suitable for real-time streaming

- **AES/GCM/NoPadding**: Galois/Counter Mode (authenticated encryption)
  - Authentication included in ciphertext
  - Higher security (combined encryption + authentication)
  - Slightly more overhead

## How to Use

### 1. Initial Setup

```bash
# Run setup wizard (interactive)
./setup.sh
```

Follow prompts to:
- Select protocol mode: RTSSP or RTSSP-SHP
- Select cipher algorithm: AES/CTR or AES/GCM
- Select key size: 128-bit or 256-bit
- Generate/regenerate certificates (for RTSSP-SHP)

### 2. Automatic Multi-Terminal Launch

```bash
# From root directory, launches server + proxy + player in separate terminals
./run.sh

# When prompted, type movie name (e.g., "cars.dat" or just "cars" or "monsters.dat")
```

**What happens:**
- Terminal 1: Server starts streaming encrypted frames
- Terminal 2: Proxy receives, decrypts, and forwards
- Terminal 3: Media player receives clear video stream
- All three run simultaneously with Ctrl+C to stop

### 3. Manual Operation (for debugging)

**Terminal 1 - Server:**
```bash
cd hjStreamServer
java hjStreamServer /full/path/to/movie/cars.dat localhost 5000
```

**Terminal 2 - Proxy:**
```bash
cd hjUDPproxy
java hjUDPproxy /full/path/to/movie/cars.dat
```

**Terminal 3 - Media Player:**
```bash
celluloid 'udp://localhost:7777'
# or: vlc 'udp://@:7777'
# or: mpv 'udp://@:7777'
```

## File Structure

```
MediaStreamingMaterials/
├── README.md                          # This file
├── setup.sh                           # Configuration & certificate generation
├── run.sh                             # Multi-terminal auto-launcher
│
├── hjStreamServer/
│   ├── hjStreamServer.java            # Main server (300+ lines)
│   ├── SHPHandshake.java              # Server-side handshake (200+ lines)
│   ├── SHPMessage.java                # Handshake message types
│   ├── CryptoUtils.java               # ECDH, ECDSA, HKDF utilities
│   ├── Cryptoconfig.conf              # Runtime configuration
│   ├── server.jks                     # Server certificate & private key
│   ├── server.truststore              # Trusted proxy certificate
│   └── movies/
│       ├── cars.dat                   # ~38 MB video file
│       └── monsters.dat               # ~33 MB video file
│
└── hjUDPproxy/
    ├── hjUDPproxy.java                # Main proxy (100+ lines)
    ├── SHPClient.java                 # Client-side handshake (200+ lines)
    ├── SHPMessage.java                # Handshake message types (copied)
    ├── CryptoUtils.java               # Crypto utilities (copied)
    ├── config.properties              # UDP forwarding config
    ├── proxy.jks                      # Proxy certificate & private key
    ├── proxy.truststore               # Trusted server certificate
    ├── *.class                        # Compiled Java files
    └── *.dat                          # Temporary decrypted frames (optional)
```

## Configuration Files

### Cryptoconfig.conf (Server)
```
mode=RTSSP-SHP
cipher.algorithm=AES/CTR/NoPadding
cipher.keysize=256
hmac.algorithm=HmacSHA256
cipher.ivsize=128
server.keystore.path=server.jks
server.keystore.password=serverpass
server.keystore.alias=server
server.keystore.keypass=serverpass
server.truststore.path=server.truststore
server.truststore.password=serverpass
handshake.proxy.host=localhost
handshake.proxy.port=8888
```

### config.properties (Proxy)
```
remote=localhost:5000
localdelivery=localhost:7777
```

## Cryptographic Details

### ECDH Key Exchange
- Curve: secp256r1 (P-256, NIST standard)
- Shared secret: 32 bytes
- Key derivation: HKDF-SHA256 (Extract + Expand)
  - Extract: 32-byte shared secret → PRK
  - Expand: PRK → 64 bytes (32 cipher key + 32 HMAC key)

### ECDSA Signatures
- Algorithm: SHA256withECDSA
- Key size: 256-bit (secp256r1)
- Usage: Mutual authentication during handshake
- Certificate validity: 365 days

### Frame Encryption
- **IV Generation**: XOR base IV with frame counter (prevents GCM reuse)
- **Unique IV per frame**: Essential for GCM mode security
- **Padding**: Not needed (CTR and GCM are stream ciphers)

### HMAC Integrity
- Algorithm: HmacSHA256
- Key size: 256 bits (or 128 bits if selected)
- Coverage: Entire encrypted payload
- Verification: Constant-time comparison (MessageDigest.isEqual)

## Handshake Protocol (RTSSP-SHP)

### 3-Message Exchange on TCP:8888

**1. CLIENT_HELLO (Proxy → Server)**
- Movie name
- Proxy's X.509 certificate (DER)
- Proxy's ECDH public key (DER)
- Supported ciphersuites: [AES/CTR/NoPadding, AES/GCM/NoPadding]
- Proxy nonce (16 bytes)
- ECDSA signature over message

**2. SERVER_HELLO (Server → Proxy)**
- Movie found flag
- Server's X.509 certificate (DER)
- Server's ECDH public key (DER)
- Selected ciphersuite
- Client nonce (echo)
- Server nonce (16 bytes)
- ECDSA signature over message

**3. CLIENT_CONFIRM (Proxy → Server)**
- Encrypted challenge (proof of shared secret)
- ECDSA signature

After successful handshake:
- Both derive identical keys via ECDH + HKDF
- Server starts streaming encrypted frames
- Proxy begins decrypting and forwarding

## Troubleshooting

### "FileNotFoundException: movies/cars.dat"
- **Cause**: Server/proxy receiving incorrect movie path
- **Fix**: Use `./run.sh` which handles paths correctly
- **Or**: Provide full absolute path when running manually

### "HMAC verification failed"
- **Cause**: Corrupted packet or wrong keys
- **Fix**: Ensure both server and proxy completed handshake with matching keys

### "Packet too short" (early versions)
- **Cause**: Buffer too small for IV + encrypted data + HMAC
- **Fix**: Already fixed (16384 byte buffers)

### "Cipher mode mismatch"
- **Cause**: Proxy using wrong cipher spec for GCM
- **Fix**: Already fixed (conditional GCMParameterSpec handling)

### Media player not receiving video
- **Cause**: Proxy not forwarding, or wrong URL format
- **Fix**: Ensure proxy shows dots (`.`) for each packet
- **Fix**: Use `udp://@:7777` (not `localhost`)

## Testing

### Quick End-to-End Verification
```bash
./run.sh
# Select: cars.dat
# Verify:
#   - Server terminal shows colons (:::) - frames being sent
#   - Proxy terminal shows dots (...) - packets forwarded
#   - Celluloid opens and plays video
```

### Performance Testing (test-performance.sh)

The `test-performance.sh` script runs automated performance benchmarks on actual encrypted streaming:

**What it does:**
- Compiles both server and proxy
- Runs 3 test configurations with different ciphers and key sizes
- Measures real performance metrics: duration, frames transmitted, throughput (fps), and throughput (Kbps)
- Generates results in `test_results/performance_results.txt`

**Test configurations:**
1. **RTSSP + AES/CTR/256**: Counter mode with 256-bit keys
2. **RTSSP + AES/GCM/256**: Authenticated encryption with 256-bit keys
3. **RTSSP + AES/GCM/128**: Authenticated encryption with 128-bit keys (same throughput, faster setup)

**How to run:**
```bash
./test-performance.sh
```

**Results example:**
```
Test 1: RTSSP+AES/CTR/256
Movie: cars.dat | Duration: 128s | Frames: 30515 | FPS: 238 | Kbps: 2509

Test 2: RTSSP+AES/GCM/256
Movie: monsters.dat | Duration: 142s | Frames: 25945 | FPS: 184 | Kbps: 1937

Test 3: RTSSP+AES/GCM/128
Movie: cars.dat | Duration: 129s | Frames: 30515 | FPS: 238 | Kbps: 2509
```

**Metrics explained:**
- **Duration**: Total streaming time (seconds)
- **Frames**: Number of video frames successfully encrypted and transmitted
- **FPS**: Frames per second throughput (target: 30+ fps for real-time)
- **Kbps**: Kilobits per second throughput

### Monitor Network (optional, requires sudo)
```bash
sudo tcpdump -i lo port 5000 or port 7777 -X
```

This shows encrypted packet contents on localhost ports for debugging.
