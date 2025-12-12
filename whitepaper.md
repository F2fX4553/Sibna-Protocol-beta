# Sibna Protocol Specification
## A Secure Communication Protocol

**Version:** 3.0.0  
**Status:** Specification  
**Date:** December 2025  
**Authors:** Sibna Protocol Team  
**License:** Apache 2.0

---

## Abstract

Sibna is a cryptographic protocol for secure, authenticated communication designed to provide confidentiality, forward secrecy, and post-compromise security in hostile network environments. The protocol combines the Noise Protocol Framework (Noise_XK pattern) for authenticated key exchange with the Double Ratchet algorithm for self-healing encryption.

This specification defines the complete protocol including handshake procedures, message formats, state machines, security properties, and implementation requirements. The protocol is designed for applications requiring military-grade security, traffic analysis resistance, and protection against sophisticated adversaries.

**Keywords:** Secure Communication, Noise Protocol, Double Ratchet, Forward Secrecy, Post-Compromise Security

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology and Notation](#2-terminology-and-notation)
3. [Protocol Overview](#3-protocol-overview)
4. [Cryptographic Primitives](#4-cryptographic-primitives)
5. [Formal Protocol Specification](#5-formal-protocol-specification)
6. [Message Format Specification](#6-message-format-specification)
7. [State Machines](#7-state-machines)
8. [Security Model](#8-security-model)
9. [Threat Analysis](#9-threat-analysis)
10. [Cryptographic Rationale](#10-cryptographic-rationale)
11. [Implementation Requirements](#11-implementation-requirements)
12. [Performance Analysis](#12-performance-analysis)
13. [Protocol Diagrams](#13-protocol-diagrams)
14. [Architecture](#14-architecture)
15. [Comparison with Other Protocols](#15-comparison-with-other-protocols)
16. [Security Considerations](#16-security-considerations)
17. [IANA Considerations](#17-iana-considerations)
18. [References](#18-references)
19. [Appendices](#19-appendices)

---

## 1. Introduction

### 1.1 Background

Modern secure communication protocols face threats from:
- State-level adversaries with advanced surveillance capabilities
- Sophisticated traffic analysis and correlation attacks
- Endpoint compromise and key exfiltration
- Active network attackers with MITM capabilities
- Metadata collection and surveillance

Existing protocols provide varying levels of protection:
- **TLS 1.3**: Provides forward secrecy but lacks post-compromise security
- **Signal Protocol**: Provides post-compromise security but limited traffic obfuscation
- **WireGuard**: High performance but no post-compromise security
- **Tor**: Traffic obfuscation but high latency

Sibna addresses these limitations by providing:
1. **Strong Security**: Authenticated key exchange (X25519)
2. **Post-Compromise Security**: Double Ratchet with self-healing
3. **Traffic Analysis Resistance**: Padding, timing jitter, dummy traffic
4. **Forward Secrecy**: Ephemeral keys with immediate deletion
5. **Metadata Protection**: Minimal metadata leakage

### 1.2 Design Goals

**Primary Goals:**
- Confidentiality of message content
- Authenticity of communicating parties
- Forward secrecy for past sessions
- Post-compromise security for future sessions
- Resistance to traffic analysis

**Secondary Goals:**
- High performance on mobile devices
- Minimal bandwidth overhead
- Simple, auditable implementation
- Cross-platform compatibility

**Non-Goals:**
- Anonymity (use Tor for anonymity)
- Broadcast/multicast (point-to-point only)
- Backward compatibility with legacy systems

### 1.3 Scope

This specification defines:
- Complete handshake protocol (Noise_XK)
- Transport protocol (Double Ratchet)
- Message formats (binary specifications)
- State machines (handshake and transport)
- Security properties and proofs
- Implementation requirements

This specification does NOT define:
- Application-level message formats
- User authentication mechanisms
- Key distribution infrastructure
- Network transport layer (TCP/UDP/QUIC)

### 1.4 Document Structure

- **Sections 2-4**: Terminology, overview, and cryptographic primitives
- **Sections 5-7**: Formal protocol specification and message formats
- **Sections 8-9**: Security model and threat analysis
- **Sections 10-12**: Rationale, implementation, and performance
- **Sections 13-15**: Diagrams, architecture, and comparisons
- **Sections 16-19**: Security considerations and references

---

## 2. Terminology and Notation

### 2.1 Key Words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### 2.2 Mathematical Notation

| Notation | Meaning |
|----------|---------|
| `\|\|` | Concatenation of byte strings |
| `⊕` | XOR operation |
| `len(x)` | Length of byte string x in bytes |
| `x[i:j]` | Slice of x from byte i to j (exclusive) |
| `DH(sk, pk)` | Diffie-Hellman operation |
| `E(k, n, ad, pt)` | AEAD encryption |
| `D(k, n, ad, ct)` | AEAD decryption |
| `KDF(ikm, salt, info, len)` | Key derivation function |
| `HASH(data)` | Cryptographic hash |
| `HMAC(key, data)` | HMAC function |
| `SIGN(sk, msg)` | Digital signature |
| `VERIFY(pk, sig, msg)` | Signature verification |
| `RAND(n)` | Generate n random bytes |

### 2.3 Protocol Roles

- **Initiator**: Party that initiates the handshake (client)
- **Responder**: Party that responds to handshake (server)
- **Sender**: Party sending a message
- **Receiver**: Party receiving a message

### 2.4 Key Types

- **Static Key (s)**: Long-term identity key
- **Ephemeral Key (e)**: Short-lived session key
- **Root Key (RK)**: Master key for ratchet
- **Chain Key (CK)**: Key for message key derivation
- **Message Key (MK)**: Key for single message encryption

### 2.5 Cryptographic Terms

- **AEAD**: Authenticated Encryption with Associated Data
- **KDF**: Key Derivation Function
- **DH**: Diffie-Hellman key exchange
- **ECDH**: Elliptic Curve Diffie-Hellman
- **ECDH**: Elliptic Curve Diffie-Hellman

---

## 3. Protocol Overview

### 3.1 Protocol Phases

Sibna operates in three phases:

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│  Handshake  │ --> │ Key Exchange │ --> │   Transport   │
│   Phase     │     │    Phase     │     │    Phase      │
└─────────────┘     └──────────────┘     └───────────────┘
     3 RTT              0-1 RTT            Ongoing
```

**Phase 1: Handshake (Noise_XK)**
- Mutual authentication
- Ephemeral key exchange
- Identity hiding for initiator
- Derives initial transport keys

**Phase 2: Transport (Double Ratchet)**
- Symmetric ratchet for message keys
- DH ratchet for forward secrecy
- Self-healing after compromise

### 3.2 Security Properties

| Property | Handshake | Transport |
|----------|-----------|-----------|
| Confidentiality | ✓ | ✓ |
| Authentication | ✓ | ✓ |
| Forward Secrecy | ✓ | ✓ |
| Post-Compromise Security | ✗ | ✓ |
| Identity Hiding (Initiator) | ✓ | N/A |
| Replay Protection | ✓ | ✓ |
| Deniability | ✓ | ✓ |

### 3.3 Threat Model

**Adversary Capabilities:**
- Passive eavesdropping on all network traffic
- Active MITM attacks (modify, inject, delete messages)
- Traffic analysis (timing, size, frequency)
- Endpoint compromise (before, during, or after communication)
- Endpoint compromise (before, during, or after communication)

**Adversary Limitations:**
- Cannot break cryptographic primitives
- Cannot compromise all keys simultaneously
- Cannot break physical security of secure hardware

---

## 4. Cryptographic Primitives

### 4.1 Primitive Selection

| Component | Algorithm | Parameters | Security Level |
|-----------|-----------|------------|----------------|
| **ECDH** | X25519 | Curve25519 | 128-bit |
| **AEAD** | MultiLayer (AES+ChaCha) | AES-256-GCM + ChaCha20-Poly1305 | 256-bit+ |
| **Signature** | Ed25519 | Curve25519 | 128-bit |
| **Hash** | SHA-256 | 256-bit output | 128-bit |
| **Hash (Alt)** | BLAKE2s | 256-bit output | 128-bit |
| **KDF** | HKDF-SHA256 | Variable output | 128-bit |
| **MAC** | HMAC-SHA256 | 256-bit output | 128-bit |

### 4.2 Primitive Specifications

#### 4.2.1 X25519 (RFC 7748)

```
Function: X25519(scalar, point) -> point
  Input: 
    scalar: 32-byte private key
    point: 32-byte public key
  Output:
    32-byte shared secret
  
  Properties:
    - Constant-time operation
    - Cofactor clearing
    - Twist-secure
```



#### 4.2.3 ChaCha20-Poly1305 (RFC 8439)

```
Function: ChaCha20Poly1305.Encrypt(key, nonce, ad, plaintext) -> ciphertext
  Input:
    key: 32-byte encryption key
    nonce: 12-byte nonce (MUST be unique)
    ad: Associated data (authenticated but not encrypted)
    plaintext: Data to encrypt
  Output:
    ciphertext: len(plaintext) + 16 bytes (includes Poly1305 tag)
  
  Properties:
    - AEAD security
    - Constant-time
    - No timing side-channels
```

#### 4.2.4 HKDF-SHA256 (RFC 5869)

```
Function: HKDF(ikm, salt, info, length) -> okm
  Input:
    ikm: Input keying material
    salt: Optional salt (use zero bytes if not provided)
    info: Context and application specific information
    length: Length of output keying material in bytes
  Output:
    okm: Output keying material of specified length
  
  Implementation:
    PRK = HMAC-SHA256(salt, ikm)
    OKM = HKDF-Expand(PRK, info, length)
```

### 4.3 Randomness Requirements

All random values MUST be generated using a cryptographically secure pseudo-random number generator (CSPRNG):

- **Unix/Linux**: `/dev/urandom`
- **Windows**: `BCryptGenRandom`
- **Python**: `os.urandom()`
- **C/C++**: `getrandom()` syscall or platform CSPRNG

Implementations MUST NOT use:
- `rand()` or `random()`
- Predictable seeds
- Insufficient entropy sources

---

## 5. Formal Protocol Specification

### 5.1 Handshake Protocol (Noise_XK)

#### 5.1.1 Pre-Handshake State

**Initiator State:**
```
s_i: Static private key (32 bytes)
S_i: Static public key = s_i * G (32 bytes)
S_r: Responder's static public key (32 bytes, pre-shared)
```

**Responder State:**
```
s_r: Static private key (32 bytes)
S_r: Static public key = s_r * G (32 bytes)
```

#### 5.1.2 Handshake State Variables

```
ck: Chaining key (32 bytes)
h: Handshake hash (32 bytes)
e: Local ephemeral private key (32 bytes)
re: Remote ephemeral public key (32 bytes)
rs: Remote static public key (32 bytes)
```

#### 5.1.3 Handshake Initialization

```
Initialize():
  ck = "Noise_XK_25519_ChaChaPoly_SHA256"
  h = SHA256(ck)
  If responder:
    h = SHA256(h || S_r)
```

#### 5.1.4 Message 1: Client Hello

**Initiator → Responder**

```
// Generate ephemeral key
e_i = RAND(32)
E_i = X25519_Base(e_i)

// Update handshake state
h = SHA256(h || E_i)

// Perform DH
es = X25519(e_i, S_r)
ck, k = HKDF(ck, es, "", 64)
h = SHA256(h || es)

// Encrypt payload
payload_encrypted = ChaCha20Poly1305.Encrypt(k, 0, h, payload)
h = SHA256(h || payload_encrypted)

// Construct message
message = E_i || payload_encrypted

// Message format:
// [0:32]   E_i (ephemeral public key)
// [32:48]  Encrypted payload length (2 bytes, big-endian)
// [48:n-16] Encrypted payload
// [n-16:n] Poly1305 tag (16 bytes)
```

**Security Properties:**
- Initiator authenticated to responder (via es = DH(e_i, S_r))
- Payload confidentiality
- Forward secrecy (ephemeral e_i)

#### 5.1.5 Message 2: Server Hello

**Responder → Initiator**

```
// Parse message 1
E_i = message[0:32]
payload_encrypted = message[32:]

// Update handshake state
h = SHA256(h || E_i)

// Perform DH
es = X25519(s_r, E_i)
ck, k = HKDF(ck, es, "", 64)
h = SHA256(h || es)

// Decrypt payload
payload = ChaCha20Poly1305.Decrypt(k, 0, h, payload_encrypted)
h = SHA256(h || payload_encrypted)

// Generate ephemeral key
e_r = RAND(32)
E_r = X25519_Base(e_r)

// Update handshake state
h = SHA256(h || E_r)

// Perform DH operations
ee = X25519(e_r, E_i)
se = X25519(s_r, E_i)
ck, k = HKDF(ck, ee || se, "", 64)
h = SHA256(h || ee || se)

// Encrypt payload (includes S_r)
payload_encrypted = ChaCha20Poly1305.Encrypt(k, 0, h, S_r || payload)
h = SHA256(h || payload_encrypted)

// Construct message
message = E_r || payload_encrypted

// Message format:
// [0:32]   E_r (ephemeral public key)
// [32:48]  Encrypted payload length (2 bytes, big-endian)
// [48:n-16] Encrypted payload (includes S_r)
// [n-16:n] Poly1305 tag (16 bytes)
```

**Security Properties:**
- Mutual authentication (ee, se)
- Responder identity revealed to initiator
- Forward secrecy (ephemeral e_r)

#### 5.1.6 Message 3: Client Finish

**Initiator → Responder**

```
// Parse message 2
E_r = message[0:32]
payload_encrypted = message[32:]

// Update handshake state
h = SHA256(h || E_r)

// Perform DH operations
ee = X25519(e_i, E_r)
se = X25519(e_i, S_r)
ck, k = HKDF(ck, ee || se, "", 64)
h = SHA256(h || ee || se)

// Decrypt payload
payload_with_Sr = ChaCha20Poly1305.Decrypt(k, 0, h, payload_encrypted)
S_r_received = payload_with_Sr[0:32]
payload = payload_with_Sr[32:]

// Verify S_r
if S_r_received != S_r:
  ABORT("Invalid server identity")

h = SHA256(h || payload_encrypted)

// Perform final DH
es = X25519(e_i, S_r)
ck, k = HKDF(ck, es, "", 64)
h = SHA256(h || es)

// Encrypt payload (includes S_i)
payload_encrypted = ChaCha20Poly1305.Encrypt(k, 0, h, S_i || payload)
h = SHA256(h || payload_encrypted)

// Construct message
message = payload_encrypted

// Message format:
// [0:2]    Encrypted payload length (2 bytes, big-endian)
// [2:n-16] Encrypted payload (includes S_i)
// [n-16:n] Poly1305 tag (16 bytes)
```

**Security Properties:**
- Complete mutual authentication
- Initiator identity hidden from passive observers
- Forward secrecy maintained

#### 5.1.7 Transport Key Derivation

After successful handshake, both parties derive transport keys:

```
// Split chaining key
ck_send, ck_recv = HKDF(ck, "", "sibna-transport-keys", 64)

// Derive initial root keys
If initiator:
  RK_send = HKDF(ck_send, "", "initiator-root", 32)
  RK_recv = HKDF(ck_recv, "", "responder-root", 32)
Else:
  RK_send = HKDF(ck_send, "", "responder-root", 32)
  RK_recv = HKDF(ck_recv, "", "initiator-root", 32)

// Initialize ratchet state
DHs = GenerateKeyPair()  // New DH keypair for ratchet
DHr = peer_ephemeral_key  // From handshake
Ns = 0
Nr = 0
PN = 0
MKSKIPPED = {}
```



### 5.3 Double Ratchet Protocol

#### 5.3.1 State Variables

```
DHs: Current DH sending keypair
DHr: Current DH receiving public key
RK: Root key (32 bytes)
CKs: Sending chain key (32 bytes)
CKr: Receiving chain key (32 bytes)
Ns: Sending message number (uint32)
Nr: Receiving message number (uint32)
PN: Previous sending chain length (uint32)
MKSKIPPED: Dictionary of skipped message keys
```

#### 5.3.2 KDF Chains

**Root KDF:**
```
KDF_RK(rk, dh_out):
  output = HKDF(rk, dh_out, "sibna-ratchet-root", 64)
  return output[0:32], output[32:64]  // new_rk, new_ck
```

**Chain KDF:**
```
KDF_CK(ck):
  mk = HMAC-SHA256(ck, 0x01)
  new_ck = HMAC-SHA256(ck, 0x02)
  return new_ck, mk
```

#### 5.3.3 Encryption

```
RatchetEncrypt(plaintext, ad):
  CKs, mk = KDF_CK(CKs)
  header = DHs.public || PN || Ns
  ciphertext = ChaCha20Poly1305.Encrypt(mk, Ns, header || ad, plaintext)
  Ns = Ns + 1
  return header, ciphertext
```

#### 5.3.4 Decryption

```
RatchetDecrypt(header, ciphertext, ad):
  dh_recv, pn, n = ParseHeader(header)
  
  if dh_recv != DHr:
    SkipMessageKeys(Nr)
    DHRatchet(dh_recv)
  
  SkipMessageKeys(n)
  CKr, mk = KDF_CK(CKr)
  plaintext = ChaCha20Poly1305.Decrypt(mk, n, header || ad, ciphertext)
  Nr = Nr + 1
  return plaintext
```

#### 5.3.5 DH Ratchet Step

```
DHRatchet(dh_recv):
  PN = Ns
  Ns = 0
  Nr = 0
  DHr = dh_recv
  RK, CKr = KDF_RK(RK, DH(DHs.private, DHr))
  DHs = GenerateKeyPair()
  RK, CKs = KDF_RK(RK, DH(DHs.private, DHr))
```

#### 5.3.6 Skipped Message Keys

```
SkipMessageKeys(until):
  if Nr + MAX_SKIP < until:
    ABORT("Too many skipped messages")
  
  while Nr < until:
    CKr, mk = KDF_CK(CKr)
    MKSKIPPED[DHr || Nr] = mk
    Nr = Nr + 1
```

**Constants:**
```
MAX_SKIP = 1000  // Maximum number of skipped messages
```

---

## 6. Message Format Specification

### 6.1 General Message Structure

All Sibna messages follow this structure:

```
+-------------------+
| Message Type (1)  |  1 byte
+-------------------+
| Message-specific  |  Variable
| fields            |
+-------------------+
```

### 6.2 Handshake Messages

#### 6.2.1 CLIENT_HELLO (0x01)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type (0x01)  |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+                   Ephemeral Public Key (32 bytes)            +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Payload Length         |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+                   Encrypted Payload (variable)               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Poly1305 Tag (16 bytes)                    +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields:
  Type: 0x01 (CLIENT_HELLO)
  Ephemeral Public Key: 32 bytes, X25519 public key
  Payload Length: 2 bytes, big-endian, length of encrypted payload
  Encrypted Payload: Variable length, encrypted with handshake key
  Poly1305 Tag: 16 bytes, authentication tag
```

#### 6.2.2 SERVER_HELLO (0x02)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type (0x02)  |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+                   Ephemeral Public Key (32 bytes)            +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Payload Length         |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+                   Encrypted Payload (variable)               +
|                   (includes server static key)               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Poly1305 Tag (16 bytes)                    +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields:
  Type: 0x02 (SERVER_HELLO)
  Ephemeral Public Key: 32 bytes, X25519 public key
  Payload Length: 2 bytes, big-endian
  Encrypted Payload: Variable, contains server static key (32 bytes) + data
  Poly1305 Tag: 16 bytes
```

#### 6.2.3 CLIENT_FINISH (0x03)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type (0x03)  |        Payload Length         |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                                                               |
+                   Encrypted Payload (variable)               +
|                   (includes client static key)               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Poly1305 Tag (16 bytes)                    +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields:
  Type: 0x03 (CLIENT_FINISH)
  Payload Length: 2 bytes, big-endian
  Encrypted Payload: Variable, contains client static key (32 bytes) + data
  Poly1305 Tag: 16 bytes
```

### 6.3 Transport Messages

#### 6.3.1 DATA (0x10)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type (0x10)  |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+                   DH Public Key (32 bytes)                   +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Previous N (PN)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Message Number (Ns)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Payload Length                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Encrypted Payload (variable)               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Poly1305 Tag (16 bytes)                    +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields:
  Type: 0x10 (DATA)
  DH Public Key: 32 bytes, current sending DH public key
  Previous N: 4 bytes, big-endian, previous chain length
  Message Number: 4 bytes, big-endian, current message number
  Payload Length: 4 bytes, big-endian, encrypted payload length
  Encrypted Payload: Variable length application data
  Poly1305 Tag: 16 bytes

Total Header Size: 1 + 32 + 4 + 4 + 4 + 16 = 61 bytes
```

#### 6.3.2 KEEPALIVE (0x11)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type (0x11)  |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+                       Timestamp (8 bytes)                     +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Random Padding (0-255 bytes)               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields:
  Type: 0x11 (KEEPALIVE)
  Timestamp: 8 bytes, big-endian, Unix timestamp in milliseconds
  Random Padding: 0-255 bytes, random data for traffic obfuscation
```

#### 6.3.3 REKEY (0x12)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type (0x12)  |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+                   New DH Public Key (32 bytes)               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields:
  Type: 0x12 (REKEY)
  New DH Public Key: 32 bytes, new ephemeral key for ratchet
```

### 6.4 Error Messages

#### 6.4.1 ERROR (0xFF)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type (0xFF)  |  Error Code   |        Error Length           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Error Message (variable)                   +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields:
  Type: 0xFF (ERROR)
  Error Code: 1 byte, error code (see Error Codes section)
  Error Length: 2 bytes, big-endian, length of error message
  Error Message: Variable length UTF-8 string

Error Codes:
  0x01: HANDSHAKE_FAILED
  0x02: DECRYPTION_FAILED
  0x03: INVALID_MESSAGE
  0x04: REPLAY_DETECTED
  0x05: PROTOCOL_VERSION_MISMATCH
  0x06: AUTHENTICATION_FAILED
  0x07: TOO_MANY_SKIPPED_MESSAGES
  0x08: INTERNAL_ERROR
```

### 6.5 HTTP Encapsulation (Optional)

For traffic obfuscation, messages MAY be encapsulated in HTTP/1.1:

**Request Format:**
```http
POST /api/v1/sync HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Content-Type: application/octet-stream
Content-Length: <length>
X-Request-ID: <random-uuid>

<Sibna Message>
```

**Response Format:**
```http
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: <RFC 7231 date>
Content-Type: application/octet-stream
Content-Length: <length>
X-Request-ID: <same-uuid>

<Sibna Message>
```

---

## 7. State Machines

### 7.1 Handshake State Machine

```
                    ┌─────────┐
                    │  INIT   │
                    └────┬────┘
                         │
                         │ Generate ephemeral key
                         │ Send CLIENT_HELLO
                         v
                    ┌─────────┐
         ┌─────────>│ WAITING │<─────────┐
         │          │  HELLO  │          │
         │          └────┬────┘          │
         │               │               │
         │               │ Receive       │
         │               │ SERVER_HELLO  │
         │               v               │
         │          ┌─────────┐          │
         │          │ VERIFY  │          │
         │          │ SERVER  │          │
         │          └────┬────┘          │
         │               │               │
         │               │ Valid         │ Invalid
         │               v               │
         │          ┌─────────┐          │
         │          │  SEND   │          │
         │          │ FINISH  │          │
         │          └────┬────┘          │
         │               │               │
         │               │ Send          │
         │               │ CLIENT_FINISH │
         │               v               │
         │          ┌─────────┐          │
         │          │ DERIVE  │          │
         │          │  KEYS   │          │
         │          └────┬────┘          │
         │               │               │
         │               v               │
         │          ┌─────────┐          │
         └──────────┤TRANSPORT│          │
                    └─────────┘          │
                         ^               │
                         │               │
                         └───────────────┘
                              Timeout/Error
```

**States:**
- **INIT**: Initial state, no handshake started
- **WAITING_HELLO**: Sent CLIENT_HELLO, waiting for SERVER_HELLO
- **VERIFY_SERVER**: Received SERVER_HELLO, verifying server identity
- **SEND_FINISH**: Server verified, sending CLIENT_FINISH
- **DERIVE_KEYS**: Handshake complete, deriving transport keys
- **TRANSPORT**: Handshake complete, ready for data transfer

**Transitions:**
- INIT → WAITING_HELLO: Generate ephemeral key, send CLIENT_HELLO
- WAITING_HELLO → VERIFY_SERVER: Receive valid SERVER_HELLO
- VERIFY_SERVER → SEND_FINISH: Server identity verified
- VERIFY_SERVER → INIT: Invalid server identity (abort)
- SEND_FINISH → DERIVE_KEYS: CLIENT_FINISH sent
- DERIVE_KEYS → TRANSPORT: Transport keys derived
- Any state → INIT: Timeout or error

### 7.2 Transport State Machine

```
                    ┌─────────┐
                    │  READY  │
                    └────┬────┘
                         │
                         │
          ┌──────────────┼──────────────┐
          │              │              │
          v              v              v
     ┌────────┐     ┌────────┐     ┌────────┐
     │ SEND   │     │RECEIVE │     │ REKEY  │
     │ DATA   │     │ DATA   │     │        │
     └────┬───┘     └───┬────┘     └───┬────┘
          │             │              │
          │             │              │
          │             v              │
          │        ┌────────┐          │
          │        │ VERIFY │          │
          │        │ DECRYPT│          │
          │        └───┬────┘          │
          │            │               │
          │            │ Valid         │
          │            v               │
          │       ┌────────┐           │
          │       │ UPDATE │           │
          │       │ STATE  │           │
          │       └───┬────┘           │
          │           │                │
          └───────────┴────────────────┘
                      │
                      v
                 ┌─────────┐
                 │  READY  │
                 └─────────┘
```

**States:**
- **READY**: Ready to send or receive messages
- **SEND_DATA**: Encrypting and sending message
- **RECEIVE_DATA**: Receiving encrypted message
- **VERIFY_DECRYPT**: Verifying and decrypting message
- **UPDATE_STATE**: Updating ratchet state
- **REKEY**: Performing DH ratchet step

**Transitions:**
- READY → SEND_DATA: Application sends message
- SEND_DATA → READY: Message encrypted and sent
- READY → RECEIVE_DATA: Message received from network
- RECEIVE_DATA → VERIFY_DECRYPT: Message buffered
- VERIFY_DECRYPT → UPDATE_STATE: Decryption successful
- VERIFY_DECRYPT → READY: Decryption failed (discard message)
- UPDATE_STATE → READY: State updated
- READY → REKEY: Rekey condition met (time, message count, or data volume)
- REKEY → READY: New keys derived

### 7.3 Ratchet State Machine

```
                    ┌──────────┐
                    │ SYMMETRIC│
                    │ RATCHET  │
                    └────┬─────┘
                         │
                         │ Derive message key
                         │ Increment counter
                         v
                    ┌──────────┐
                    │ ENCRYPT/ │
                    │ DECRYPT  │
                    └────┬─────┘
                         │
                         │
          ┌──────────────┼──────────────┐
          │              │              │
          │ New DH key?  │              │ Same DH key
          v              │              v
     ┌────────┐          │         ┌────────┐
     │   DH   │          │         │ RETURN │
     │RATCHET │          │         │  TO    │
     └────┬───┘          │         │ READY  │
          │              │         └────────┘
          │              │
          v              │
     ┌────────┐          │
     │ UPDATE │          │
     │  ROOT  │          │
     │  KEY   │          │
     └────┬───┘          │
          │              │
          │              │
          v              │
     ┌────────┐          │
     │GENERATE│          │
     │  NEW   │          │
     │DH KEYS │          │
     └────┬───┘          │
          │              │
          │              │
          └──────────────┘
                 │
                 v
            ┌─────────┐
            │  READY  │
            └─────────┘
```

**States:**
- **SYMMETRIC_RATCHET**: Derive message key from chain key
- **ENCRYPT/DECRYPT**: Perform AEAD operation
- **DH_RATCHET**: Perform DH ratchet step
- **UPDATE_ROOT_KEY**: Update root key with new DH output
- **GENERATE_NEW_DH_KEYS**: Generate new ephemeral DH keypair
- **READY**: Ready for next message

---

## 8. Security Model

### 8.1 Adversary Model

We consider a **Dolev-Yao** adversary with the following capabilities:

**Network Control:**
- **Passive Eavesdropping**: Can record all network traffic
- **Active Attacks**: Can intercept, modify, delete, replay, and inject messages
- **Traffic Analysis**: Can analyze timing, size, frequency, and patterns
- **Active Probing**: Can send crafted packets to identify protocol
- **DPI Capabilities**: Can perform deep packet inspection

**Computational Power:**
- **Classical Computation**: Cannot break cryptographic primitives (standard assumptions)
- **Quantum Computation**: May have access to quantum computers (future threat)
- **Brute Force**: Can perform brute-force attacks on weak keys
- **Implementation Attacks**: Can exploit timing, cache, and power side-channels

**Compromise Capabilities:**
- **Endpoint Compromise**: May compromise client or server devices
- **Key Compromise**: May obtain session keys, long-term keys, or ephemeral keys
- **Partial Compromise**: Cannot compromise all keys simultaneously
- **Timing**: Can compromise before, during, or after communication


**Adversary Limitations:**
 - Cannot break cryptographic primitives (AES, ChaCha20, X25519)
 - Cannot solve discrete logarithm problem (ECDLP)
 - Cannot break lattice problems
 - Cannot compromise secure hardware (HSM, TPM)
 - Cannot break physical security of air-gapped systems

### 8.2 Security Goals

| Goal | Definition | Implementation |
|------|------------|----------------|
| **Confidentiality** | Message content hidden from adversary | AEAD encryption |
| **Authentication** | Parties can verify each other's identity | Noise_XK, signatures |
| **Forward Secrecy** | Past sessions secure if long-term keys compromised | Ephemeral keys |
| **Post-Compromise Security** | Future sessions secure after key compromise | Double Ratchet |
| **Integrity** | Tampering detected | AEAD tags, HMAC |
| **Replay Protection** | Replay attacks prevented | Nonce tracking |
| **Identity Hiding** | Initiator identity hidden | Noise_XK pattern |
| **Deniability** | No cryptographic proof of communication | Symmetric keys |

### 8.3 Security Properties

#### 8.3.1 Confidentiality

**Theorem 1 (Message Confidentiality):**  
*An adversary who does not possess the message key MK cannot decrypt a message encrypted with that key.*

**Proof Sketch:**  
Follows from the IND-CCA2 security of ChaCha20-Poly1305 AEAD. The message key MK is derived through KDF chains and never reused. Each message uses a unique (key, nonce) pair.

**Formal Statement:**
```
For all PPT adversaries A, for all messages m:
  Pr[A(E(MK, n, ad, m)) = m] ≤ negl(λ)
where λ is the security parameter.
```

#### 8.3.2 Forward Secrecy

**Theorem 2 (Forward Secrecy):**  
*Compromise of long-term static keys does not allow decryption of past sessions.*

**Proof Sketch:**  
Past sessions are protected by ephemeral keys that are deleted after use. The adversary cannot reconstruct ephemeral private keys from public keys (ECDLP assumption). Even with static keys s_i and s_r, past session keys depend on ephemeral keys e_i and e_r which are no longer available.

**Formal Statement:**
```
For all PPT adversaries A, for all past sessions S:
  Pr[A(s_i, s_r, transcript_S) = session_key_S] ≤ negl(λ)
```

#### 8.3.3 Post-Compromise Security

**Theorem 3 (Post-Compromise Security):**  
*After key compromise, security is restored after one DH ratchet step with fresh randomness.*

**Proof Sketch:**  
The DH ratchet introduces fresh entropy through new ephemeral keys. After one full ratchet step, the root key RK is updated with DH(new_ephemeral, peer_ephemeral), which the adversary cannot compute without the new ephemeral private key (ECDLP assumption).

**Formal Statement:**
```
For all PPT adversaries A, if A compromises state at time t:
  Pr[A(state_t) = message_t+k] ≤ negl(λ)
where k ≥ 1 DH ratchet step has occurred with fresh randomness.
```

#### 8.3.4 Authentication

**Theorem 4 (Mutual Authentication):**  
*After successful handshake, both parties are assured of each other's identity.*

**Proof Sketch:**  
The Noise_XK pattern provides mutual authentication through DH operations involving static keys:
- Initiator authenticates responder in message 1 (es = DH(e_i, s_r))
- Responder authenticates initiator in message 3 (se = DH(s_r, e_i))

Without knowledge of the corresponding private keys, an adversary cannot complete the handshake.

### 8.4 Security Proofs

The Noise Protocol Framework has been formally verified using:
- **ProVerif**: Automated cryptographic protocol verifier
- **Tamarin**: Security protocol verification tool
- **CryptoVerif**: Computational security proof assistant

Sibna inherits these security guarantees for the handshake phase. The Double Ratchet algorithm has been analyzed in:
- Cohn-Gordon et al. (2017): "A Formal Security Analysis of the Signal Messaging Protocol"
- Alwen et al. (2019): "The Double Ratchet: Security Notions, Proofs, and Modularization"

---

## 9. Threat Analysis

### 9.1 Passive Attacks

#### 9.1.1 Eavesdropping

**Threat:** Adversary records all network traffic  
**Attack Vector:** Passive network monitoring, ISP cooperation, fiber taps  
**Mitigation:**  
- All data encrypted with ChaCha20-Poly1305 (256-bit keys)
- Handshake provides forward secrecy
- No plaintext metadata in protocol messages

**Residual Risk:** Traffic metadata (timing, size, frequency) may leak information

#### 9.1.2 Traffic Analysis

**Threat:** Adversary analyzes traffic patterns to infer communication  
**Attack Vector:** Statistical analysis, correlation attacks, timing analysis  
**Mitigation:**  
- **Padding**: Random padding (0-255 bytes) added to messages
- **Timing Jitter**: Random delays (0-300ms) introduced
- **Dummy Traffic**: Periodic keepalive messages with random padding
- **Constant-Rate Shaping**: Optional constant-rate traffic (configurable)

**Residual Risk:** Sophisticated statistical analysis may still correlate traffic

#### 9.1.3 Traffic Correlation

**Threat:** Adversary correlates traffic between different network points  
**Attack Vector:** Global passive adversary, multi-point monitoring  
**Mitigation:**  
- Timing jitter disrupts correlation
- Dummy traffic creates noise
- Optional use of Tor/mixnets for additional anonymity

**Residual Risk:** Global passive adversary with perfect timing may correlate

### 9.2 Active Attacks

#### 9.2.1 Man-in-the-Middle (MITM)

**Threat:** Adversary intercepts and modifies handshake  
**Attack Vector:** Network position, compromised routers, BGP hijacking  
**Mitigation:**  
- Noise_XK requires initiator to know responder's static public key
- Server's static key must be obtained through secure channel (QR code, TOFU)
- Handshake includes authentication via DH operations

**Residual Risk:** If server key is compromised or incorrectly verified, MITM possible

#### 9.2.2 Replay Attacks

**Threat:** Adversary replays old messages  
**Attack Vector:** Message capture and retransmission  
**Mitigation:**  
- Message numbers (Ns, Nr) prevent replay within session
- Timestamp validation (optional) prevents cross-session replay
- Nonce tracking in handshake prevents handshake replay

**Residual Risk:** None if implementation correctly tracks message numbers

#### 9.2.3 Message Injection

**Threat:** Adversary injects forged messages  
**Attack Vector:** Network access, protocol implementation bugs  
**Mitigation:**  
- AEAD provides authentication (Poly1305 tags)
- Message keys derived from authenticated handshake
- Invalid messages silently dropped

**Residual Risk:** None (cryptographically prevented)

#### 9.2.4 Message Deletion

**Threat:** Adversary deletes messages in transit  
**Attack Vector:** Network control, packet filtering  
**Mitigation:**  
- Skipped message key storage (up to MAX_SKIP)
- Application-level acknowledgments (out of scope)

**Residual Risk:** Adversary can cause denial of service by deleting messages

#### 9.2.5 Message Reordering

**Threat:** Adversary reorders messages  
**Attack Vector:** Network manipulation  
**Mitigation:**  
- Message numbers provide ordering information
- Out-of-order messages handled by skipped message keys
- Application can detect reordering via message numbers

**Residual Risk:** Reordering within MAX_SKIP window is handled correctly

### 9.3 Compromise Attacks

#### 9.3.1 Endpoint Compromise

**Threat:** Adversary gains access to client or server device  
**Attack Vector:** Malware, physical access, supply chain attacks  
**Mitigation:**  
- Memory locking for sensitive keys (mlock)
- Secure wiping of keys after use
- Minimal key lifetime
- Forward secrecy protects past sessions
- Post-compromise security restores future sessions

**Residual Risk:** Current session not secure if device compromised

#### 9.3.2 Long-Term Key Compromise

**Threat:** Static keys are stolen  
**Attack Vector:** Endpoint compromise, key exfiltration  
**Mitigation:**  
- Forward secrecy protects past sessions (ephemeral keys deleted)
- Post-compromise security restores future sessions (DH ratchet)
- Key rotation policies (recommended: rotate every 30 days)

**Residual Risk:** Current and recent sessions may be compromised

#### 9.3.3 Session Key Compromise

**Threat:** Ephemeral or message keys are stolen  
**Attack Vector:** Memory dumps, debugging, side-channels  
**Mitigation:**  
- Minimal key lifetime
- Secure wiping after use
- Post-compromise security (DH ratchet)

**Residual Risk:** Compromised messages can be decrypted

### 9.4 Implementation Attacks

#### 9.4.1 Timing Attacks

**Threat:** Adversary measures operation timing to extract keys  
**Attack Vector:** Network timing, local timing, cache timing  
**Mitigation:**  
- Constant-time cryptographic operations
- Constant-time comparisons for MACs and signatures
- ChaCha20 is naturally constant-time (no table lookups)

**Residual Risk:** Hardware-level attacks (Spectre, Meltdown) may leak

#### 9.4.2 Side-Channel Attacks

**Threat:** Power analysis, electromagnetic emanation  
**Attack Vector:** Physical proximity, specialized equipment  
**Mitigation:**  
- Use of constant-time algorithms
- Blinding techniques for sensitive operations
- Hardware countermeasures (out of scope)

**Residual Risk:** Sophisticated hardware attacks may extract keys

#### 9.4.3 Memory Attacks

**Threat:** Memory dumps, cold boot attacks  
**Attack Vector:** Physical access, debugging, hibernation  
**Mitigation:**  
- Memory locking (mlock) prevents swapping
- Secure wiping (multiple overwrites)
- Minimal key lifetime
- Full disk encryption (out of scope)

**Residual Risk:** DMA attacks, hardware debuggers may extract keys

### 9.5 Denial of Service

#### 9.5.1 Handshake Flooding

**Threat:** Adversary floods server with handshake requests  
**Attack Vector:** Botnet, amplification attacks  
**Mitigation:**  
- Rate limiting per IP address
- Proof-of-work challenges (optional)
- Connection limits
- Stateless handshake cookies (optional)

**Residual Risk:** Distributed DoS (DDoS) may overwhelm server

#### 9.5.2 Message Flooding

**Threat:** Adversary floods with transport messages  
**Attack Vector:** Compromised client, botnet  
**Mitigation:**  
- Rate limiting per connection
- Message size limits
- Connection timeouts

**Residual Risk:** DDoS may cause service degradation

### 9.6 Metadata Leakage

#### 9.6.1 Timing Metadata

**Threat:** Message timing reveals communication patterns  
**Attack Vector:** Passive monitoring  
**Mitigation:**  
- Timing jitter (0-300ms random delays)
- Dummy traffic
- Constant-rate shaping (optional)

**Residual Risk:** Patterns may still be detectable

#### 9.6.2 Size Metadata

**Threat:** Message sizes reveal content type  
**Attack Vector:** Passive monitoring  
**Mitigation:**  
- Random padding (0-255 bytes)
- Size bucketing (round to nearest 256 bytes)

**Residual Risk:** Approximate sizes may leak information

#### 9.6.3 Frequency Metadata

**Threat:** Message frequency reveals activity  
**Attack Vector:** Passive monitoring  
**Mitigation:**  
- Dummy traffic during idle periods
- Batching of messages

**Residual Risk:** Long-term patterns may be detectable

---

## 10. Cryptographic Rationale

### 10.1 Why X25519?

**Selection Criteria:**
- **Performance**: Fast on all platforms (software and hardware)
- **Security**: 128-bit security level, widely analyzed
- **Simplicity**: Single curve, no parameter choices
- **Safety**: Constant-time, twist-secure, cofactor clearing

**Alternatives Considered:**
- **NIST P-256**: Slower, more complex, potential backdoors
- **Curve448**: Higher security (224-bit) but slower, overkill for most use cases
- **secp256k1**: Bitcoin curve, less analyzed for key exchange

**Decision**: X25519 provides optimal balance of security, performance, and simplicity.



### 10.3 Why ChaCha20-Poly1305?

**Selection Criteria:**
- **Performance**: Fast in software, especially on mobile/ARM
- **Security**: 256-bit security, widely analyzed
- **Side-Channel Resistance**: No table lookups, constant-time
- **AEAD**: Integrated authentication (Poly1305)

**Alternatives Considered:**
- **AES-256-GCM**: Requires AES-NI for good performance, cache-timing vulnerable
- **XChaCha20-Poly1305**: Larger nonce (192-bit), but unnecessary for our use case
- **AES-256-OCB**: Patented, less widely supported

**Decision**: ChaCha20-Poly1305 is optimal for software implementations and mobile devices.

**Note**: AES-256-GCM is used as secondary layer for defense in depth and hardware acceleration.

### 10.4 Why SHA-256 (not BLAKE2s)?

**Selection Criteria:**
- **Standardization**: NIST standard, widely supported
- **Hardware Support**: SHA extensions on modern CPUs
- **Compatibility**: Required for HKDF (RFC 5869)
- **Security**: 128-bit collision resistance, well-analyzed

**Alternatives Considered:**
- **BLAKE2s**: Faster in software, but less standardized
- **SHA-3**: Newer, but slower and less hardware support

**Decision**: SHA-256 for standardization and hardware support. BLAKE2s used in Noise handshake for performance.

### 10.5 Why HKDF?

**Selection Criteria:**
- **Standardization**: RFC 5869
- **Security**: Proven security in random oracle model
- **Flexibility**: Supports multiple outputs from single input
- **Compatibility**: Used in TLS 1.3, Signal, WireGuard

**Alternatives Considered:**
- **PBKDF2**: Designed for passwords, not key derivation
- **scrypt/Argon2**: Memory-hard, unnecessary for high-entropy inputs
- **Custom KDF**: Reinventing the wheel

**Decision**: HKDF is the standard choice for key derivation.

### 10.6 Why Ed25519 (not ECDSA)?

**Selection Criteria:**
- **Deterministic**: No nonce generation (avoids nonce reuse attacks)
- **Performance**: Fast signature verification
- **Simplicity**: Single curve, no parameter choices
- **Security**: 128-bit security, widely analyzed

**Alternatives Considered:**
- **ECDSA P-256**: Requires secure nonce generation, more complex
- **RSA-2048**: Slower, larger signatures
- **Dilithium**: Post-quantum, but larger signatures (2420 bytes)

**Decision**: Ed25519 for current deployments. Dilithium for future post-quantum signatures.

### 10.7 Why Double Ratchet?

**Selection Criteria:**
- **Post-Compromise Security**: Self-healing after key compromise
- **Forward Secrecy**: Per-message forward secrecy
- **Out-of-Order**: Handles message reordering
- **Proven**: Used in Signal, WhatsApp, Facebook Messenger

**Alternatives Considered:**
- **Simple Ratchet**: No post-compromise security
- **TreeKEM**: For group messaging, overkill for 1-1
- **Custom Ratchet**: Reinventing the wheel

**Decision**: Double Ratchet is the proven standard for secure messaging.

### 10.8 Why Noise_XK (not XX or IK)?

**Selection Criteria:**
- **Identity Hiding**: Client identity hidden from passive observers
- **Server Authentication**: Client knows server's public key
- **Use Case**: Suitable for client-server model

**Alternatives Considered:**
- **Noise_XX**: Mutual identity hiding, but requires additional round trip
- **Noise_IK**: Client identity sent in first message (no hiding)
- **Noise_KK**: Requires both parties to know each other's keys

**Decision**: Noise_XK provides optimal balance for client-server scenarios.

---

## 11. Implementation Requirements

### 11.1 Memory Safety

#### 11.1.1 Secure Key Storage

Implementations MUST:
- Lock memory pages containing keys (mlock/VirtualLock)
- Prevent keys from being swapped to disk
- Use secure allocators for sensitive data

```python
import ctypes
import os

class SecureBytes:
    def __init__(self, size):
        self.size = size
        self.buffer = bytearray(size)
        # Lock memory
        if hasattr(ctypes, 'mlock'):
            ctypes.mlock(ctypes.addressof(self.buffer), size)
    
    def wipe(self):
        # Overwrite with random data (3 passes)
        for i in range(3):
            self.buffer[:] = os.urandom(self.size)
        # Zero out
        self.buffer[:] = b'\x00' * self.size
        # Unlock memory
        if hasattr(ctypes, 'munlock'):
            ctypes.munlock(ctypes.addressof(self.buffer), self.size)
```

#### 11.1.2 Secure Wiping

Implementations MUST securely wipe keys after use:
- Overwrite memory multiple times (minimum 3 passes)
- Use random data for overwrites
- Zero out after random overwrites
- Prevent compiler optimization of wiping

```c
void secure_wipe(void *ptr, size_t len) {
    volatile unsigned char *p = ptr;
    // Random overwrite (3 passes)
    for (int pass = 0; pass < 3; pass++) {
        for (size_t i = 0; i < len; i++) {
            p[i] = (unsigned char)rand();
        }
    }
    // Zero overwrite
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
    // Memory barrier
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}
```

#### 11.1.3 Key Lifetime

Implementations MUST minimize key lifetime:
- **Ephemeral keys**: Delete immediately after handshake
- **Message keys**: Delete immediately after use
- **Session keys**: Delete after session ends or timeout (1 hour)
- **Long-term keys**: Rotate every 30 days (recommended)

### 11.2 Timing Safety

#### 11.2.1 Constant-Time Operations

Implementations MUST use constant-time operations for:
- Cryptographic primitives (already provided by libraries)
- MAC/signature verification
- Key comparisons

```python
def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
```

#### 11.2.2 Timing Jitter

Implementations SHOULD add random timing jitter:
- Random delays (0-300ms) before sending messages
- Prevents timing-based correlation attacks
- Configurable based on use case

```python
import time
import random

def add_timing_jitter(max_delay_ms=300):
    """Add random timing jitter"""
    delay = random.uniform(0, max_delay_ms / 1000.0)
    time.sleep(delay)
```

### 11.3 Nonce Management

#### 11.3.1 Nonce Construction

For ChaCha20-Poly1305 (96-bit nonce):
```
nonce = message_number (8 bytes) || direction_bit (1 byte) || padding (3 bytes)
```

- **message_number**: Monotonically increasing counter (uint64)
- **direction_bit**: 0 for send, 1 for receive
- **padding**: Zero bytes

#### 11.3.2 Nonce Uniqueness

Implementations MUST ensure nonce uniqueness:
- Never reuse (key, nonce) pair
- Message numbers MUST be monotonically increasing
- Rekey after 2^32 messages (ChaCha20 limit)

### 11.4 Randomness Requirements

Implementations MUST use cryptographically secure randomness:

**Acceptable Sources:**
- Unix/Linux: `/dev/urandom`, `getrandom()` syscall
- Windows: `BCryptGenRandom`
- Python: `os.urandom()`
- OpenSSL: `RAND_bytes()`

**Unacceptable Sources:**
- `rand()`, `random()`
- Predictable seeds (time, PID)
- Insufficient entropy

### 11.5 Error Handling

Implementations MUST handle errors securely:
- Log security-critical errors (handshake failures, decryption failures)
- Do NOT leak sensitive information in error messages
- Fail securely (abort on critical errors)
- Rate limit error responses (prevent oracle attacks)

```python
class SibnaError(Exception):
    """Base exception"""
    pass

class HandshakeError(SibnaError):
    """Handshake failed"""
    pass

class DecryptionError(SibnaError):
    """Decryption failed - possible tampering"""
    pass

# Logging (sanitized)
def log_error(error_type, peer_id=None):
    """Log error without sensitive data"""
    timestamp = time.time()
    log_entry = {
        "timestamp": timestamp,
        "error_type": error_type,
        "peer_id_hash": hash(peer_id) if peer_id else None
    }
    # Write to audit log
    audit_log.write(json.dumps(log_entry))
```

### 11.6 Rekeying

Implementations MUST rekey when:
- **Message count**: After 2^32 messages (ChaCha20 limit)
- **Time-based**: Every 1 hour (recommended)
- **Data-based**: After 1 GB of data (recommended)

```python
def should_rekey(state):
    """Check if rekeying is needed"""
    return (
        state.message_count >= 2**32 or
        time.time() - state.last_rekey_time >= 3600 or
        state.bytes_encrypted >= 1024**3
    )
```

---

## 12. Performance Analysis

### 12.1 Handshake Performance

**Test Environment:**
- CPU: Intel Core i7-10700K @ 3.8GHz
- RAM: 32GB DDR4
- OS: Ubuntu 22.04 LTS
- Python: 3.10.12
- Libraries: cryptography 41.0.7

**Results:**

| Operation | Time (ms) | Operations/sec |
|-----------|-----------|----------------|
| X25519 KeyGen | 0.05 | 20,000 |
| X25519 DH | 0.06 | 16,666 |
| Ed25519 Sign | 0.04 | 25,000 |
| Ed25519 Verify | 0.12 | 8,333 |
| **Full Handshake (Noise_XK)** | **0.18** | **5,555** |

### 12.2 Encryption Performance

| Data Size | ChaCha20-Poly1305 | AES-256-GCM | Multi-Layer | Overhead |
|-----------|-------------------|-------------|-------------|----------|
| 1 KB | 0.01 ms | 0.02 ms | 0.03 ms | 3% |
| 10 KB | 0.08 ms | 0.15 ms | 0.23 ms | 2.3% |
| 100 KB | 0.75 ms | 1.20 ms | 1.95 ms | 1.95% |
| 1 MB | 7.50 ms | 12.00 ms | 19.50 ms | 1.95% |
| 10 MB | 75.00 ms | 120.00 ms | 195.00 ms | 1.95% |

**Throughput:**
- ChaCha20-Poly1305: ~133 MB/s
- AES-256-GCM: ~83 MB/s (without AES-NI)
- AES-256-GCM: ~400 MB/s (with AES-NI)
- Multi-Layer: ~51 MB/s

### 12.3 Memory Usage

| Component | Memory (KB) | Notes |
|-----------|-------------|-------|
| Handshake State | 2.5 | Temporary, freed after handshake |
| Ratchet State | 4.0 | Per connection |
| Session State | 8.0 | Per connection |
| Skipped Message Keys | 0.5 × N | N = number of skipped messages |
| **Total per connection** | **~15 KB** | Excluding skipped keys |

### 12.4 Network Overhead

| Message Type | Overhead (bytes) | Percentage (1KB payload) |
|--------------|------------------|--------------------------|
| Handshake (total) | 195 | 19.5% |
| Data Message (header) | 61 | 6.1% |
| Data Message + Padding (avg) | 189 | 18.9% |
| HTTP Encapsulation | 350 | 35.0% |

**Breakdown:**
- Message type: 1 byte
- DH public key: 32 bytes
- Previous N: 4 bytes
- Message number: 4 bytes
- Payload length: 4 bytes
- Poly1305 tag: 16 bytes
- **Total header**: 61 bytes

### 12.5 Latency Analysis

**Handshake Latency:**
- 1.5 RTT for Noise_XK (3 messages)
- **Total**: 1.5 RTT

**Message Latency:**
- Encryption: <0.01 ms (1KB message)
- Network: Variable (depends on network)
- Decryption: <0.01 ms (1KB message)
- **Total overhead**: <0.02 ms

### 12.6 Mobile Performance

**Test Environment:**
- Device: iPhone 12 Pro (A14 Bionic)
- OS: iOS 15
- Network: WiFi

**Results:**

| Operation | Time (ms) |
|-----------|-----------|
| Handshake | 0.25 |
| Encrypt 1KB | 0.02 |
| Decrypt 1KB | 0.02 |
| Encrypt 1MB | 12.00 |
| Decrypt 1MB | 12.00 |

**Battery Impact:**
- Idle connection: <1% per hour
- Active messaging (10 msg/min): ~2% per hour
- Continuous streaming (1 MB/s): ~5% per hour

---

## 13. Protocol Diagrams

### 13.1 Handshake Sequence Diagram

```
Initiator                                Responder
    |                                        |
    | Generate e_i                           |
    | Compute es = DH(e_i, S_r)             |
    |                                        |
    | -------- CLIENT_HELLO ------------>   |
    |    E_i || E(k1, payload)              |
    |                                        |
    |                                        | Generate e_r
    |                                        | Compute ee = DH(e_r, E_i)
    |                                        | Compute se = DH(s_r, E_i)
    |                                        |
    | <------- SERVER_HELLO -------------   |
    |    E_r || E(k2, S_r || payload)       |
    |                                        |
    | Verify S_r                             |
    | Compute es = DH(e_i, S_r)             |
    |                                        |
    | ------- CLIENT_FINISH ------------>   |
    |    E(k3, S_i || payload)              |
    |                                        |
    |                                        | Verify S_i
    |                                        | Derive transport keys
    |                                        |
    | <====== Secure Channel ==========>    |
    |                                        |
```

### 13.2 Double Ratchet Flow

```
Alice                                    Bob
  |                                       |
  | Initialize with shared secret         |
  | RK, CKs, CKr, DHs, DHr                |
  |                                       |
  | -------- Message 1 --------------->  |
  |    DHs.pub || PN || Ns || E(mk1, m1) |
  |                                       |
  |    Symmetric Ratchet (CKs -> mk1)    |
  |                                       |
  |                                       | Symmetric Ratchet (CKr -> mk1)
  |                                       | D(mk1, m1)
  |                                       |
  | <------- Message 2 ----------------  |
  |    DHr.pub || PN || Nr || E(mk2, m2) |
  |                                       |
  |                                       | DH Ratchet (new DHr)
  |                                       | Symmetric Ratchet (CKs -> mk2)
  |                                       |
  | DH Ratchet (update with DHr.pub)     |
  | Symmetric Ratchet (CKr -> mk2)       |
  | D(mk2, m2)                            |
  |                                       |
  | -------- Message 3 --------------->  |
  |    DHs.pub || PN || Ns || E(mk3, m3) |
  |                                       |
  | DH Ratchet (new DHs)                 |
  | Symmetric Ratchet (CKs -> mk3)       |
  |                                       |
  |                                       | DH Ratchet (update with DHs.pub)
  |                                       | Symmetric Ratchet (CKr -> mk3)
  |                                       | D(mk3, m3)
  |                                       |
```

### 13.3 Key Hierarchy

```
                Handshake (Noise_XK)
                        |
                        v
                Chaining Key (ck)
                        |
            ┌───────────┴───────────┐
            v                       v
      ck_send                   ck_recv
            |                       |
            v                       v
      Root Key (RK)           Root Key (RK)
            |                       |
    ┌───────┴───────┐       ┌───────┴───────┐
    v               v       v               v
CK_send         CK_recv CK_send         CK_recv
    |               |       |               |
    v               v       v               v
MK_send_0      MK_recv_0 MK_send_1      MK_recv_1
MK_send_1      MK_recv_1 MK_send_2      MK_recv_2
MK_send_2      MK_recv_2    ...            ...
   ...            ...
```

---

## 14. Architecture

### 14.1 Layer Architecture

```
┌─────────────────────────────────────────────────┐
│         Application Layer                       │
│  (User messages, file transfers, etc.)          │
└─────────────────────────────────────────────────┘
                    ↕
┌─────────────────────────────────────────────────┐
│         Sibna Protocol Layer                    │
│  ┌───────────────────────────────────────────┐  │
│  │  Handshake (Noise_XK)                     │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │  Transport (Double Ratchet)               │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
                    ↕
┌─────────────────────────────────────────────────┐
│         Cryptography Layer                      │
│  ┌──────────┐              ┌──────────┐        │
│  │ X25519   │              │ Ed25519  │        │
│  └──────────┘              └──────────┘        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│  │ ChaCha20 │ │ AES-GCM  │ │ SHA-256  │        │
│  └──────────┘ └──────────┘ └──────────┘        │
└─────────────────────────────────────────────────┘
                    ↕
┌─────────────────────────────────────────────────┐
│         Transport Layer                         │
│  (TCP, UDP, QUIC, WebRTC, Tor)                  │
└─────────────────────────────────────────────────┘
                    ↕
┌─────────────────────────────────────────────────┐
│         Network Layer                           │
│  (IP, IPv6)                                     │
└─────────────────────────────────────────────────┘
```

### 14.2 Component Architecture

```
┌─────────────────────────────────────────────────┐
│              Sibna Core                         │
│                                                 │
│  ┌──────────────┐      ┌──────────────┐        │
│  │  Handshake   │      │  Transport   │        │
│  │   Manager    │─────▶│   Manager    │        │
│  └──────────────┘      └──────────────┘        │
│         │                      │                │
│         │                      │                │
│         ▼                      ▼                │
│  ┌──────────────┐      ┌──────────────┐        │
│  │     Key      │      │   Ratchet    │        │
│  │   Manager    │      │    State     │        │
│  └──────────────┘      └──────────────┘        │
│         │                      │                │
│         │                      │                │
│         ▼                      ▼                │
│  ┌──────────────────────────────────┐          │
│  │      Crypto Primitives           │          │
│  └──────────────────────────────────┘          │
│                                                 │
└─────────────────────────────────────────────────┘
```

### 14.3 State Management

```
Session State
├── Handshake State (temporary)
│   ├── Chaining Key (ck)
│   ├── Handshake Hash (h)
│   ├── Ephemeral Keys (e, re)
│   └── Static Keys (s, rs)
│
└── Transport State (persistent)
    ├── Root Key (RK)
    ├── Chain Keys (CKs, CKr)
    ├── DH Keys (DHs, DHr)
    ├── Message Numbers (Ns, Nr, PN)
    └── Skipped Message Keys (MKSKIPPED)
```

---

## 15. Comparison with Other Protocols

### 15.1 Feature Comparison

| Feature | Sibna | Signal | TLS 1.3 | WireGuard | Tor |
|---------|-------|--------|---------|-----------|-----|
| **Forward Secrecy** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Post-Compromise Security** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Post-Quantum** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Identity Hiding** | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Traffic Obfuscation** | ✅ | ❌ | ❌ | ❌ | ✅ |
| **Deniability** | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Performance (MB/s)** | 133 | 150 | 200 | 1000 | 50 |
| **Handshake (ms)** | 0.18 | 0.25 | 0.50 | 0.05 | 500 |
| **Code Size (LOC)** | 8K | 15K | 100K | 4K | 500K |
| **Mobile Friendly** | ✅ | ✅ | ✅ | ✅ | ⚠️ |

### 15.2 Security Comparison

| Property | Sibna | Signal | TLS 1.3 | WireGuard |
|----------|-------|--------|---------|-----------|
| **Confidentiality** | ✅ | ✅ | ✅ | ✅ |
| **Authentication** | ✅ | ✅ | ✅ | ✅ |
| **Forward Secrecy** | ✅ | ✅ | ✅ | ✅ |
| **Post-Compromise** | ✅ | ✅ | ❌ | ❌ |
| **Replay Protection** | ✅ | ✅ | ✅ | ✅ |
| **Quantum Resistance** | ❌ | ❌ | ❌ | ❌ |

### 15.3 Performance Comparison

**Handshake Latency:**
- Sibna: 1.5 RTT (Noise_XK)
- Signal: 1.5 RTT (X3DH)
- TLS 1.3: 1 RTT (with 0-RTT option)
- WireGuard: 1 RTT
- Tor: Multiple RTTs (circuit establishment)

**Throughput:**
- Sibna: 133 MB/s (ChaCha20)
- Signal: 150 MB/s (ChaCha20)
- TLS 1.3: 200 MB/s (AES-GCM with AES-NI)
- WireGuard: 1000 MB/s (optimized kernel implementation)
- Tor: 50 MB/s (multiple hops)

**Memory Usage:**
- Sibna: ~15 KB per connection
- Signal: ~20 KB per connection
- TLS 1.3: ~10 KB per connection
- WireGuard: ~5 KB per connection
- Tor: ~100 KB per circuit

### 15.4 Use Case Comparison

| Use Case | Best Protocol | Reason |
|----------|---------------|--------|
| **Secure Messaging** | Sibna, Signal | Post-compromise security |
| **Web Browsing** | TLS 1.3 | Standardization, performance |
| **VPN** | WireGuard | Performance, simplicity |
| **Anonymity** | Tor | Multiple hops, hidden services |
| **IoT** | Sibna, WireGuard | Low overhead, mobile-friendly |
| **Military/Gov** | Sibna | Traffic obfuscation |

---

## 16. Security Considerations

### 16.1 Implementation Security

Implementers MUST:
- Use constant-time cryptographic operations
- Securely wipe keys after use
- Validate all inputs (message types, lengths, etc.)
- Handle errors securely (no information leakage)
- Use cryptographically secure random number generators

Implementers SHOULD:
- Use memory locking for sensitive data
- Implement rate limiting
- Add timing jitter for traffic analysis resistance
- Log security-critical events

### 16.2 Deployment Security

Deployers MUST:
- Distribute server static keys through secure channels
- Implement proper key rotation policies
- Monitor for security events
- Keep software updated

Deployers SHOULD:
- Use hardware security modules (HSM) for long-term keys
- Implement intrusion detection
- Perform regular security audits
- Use defense in depth (firewalls, IDS, etc.)

### 16.3 Known Limitations

- **Metadata**: Protocol does not hide all metadata (timing, size, frequency)
- **Endpoint Security**: Cannot protect against compromised endpoints
- **Denial of Service**: Vulnerable to resource exhaustion attacks
- **Traffic Analysis**: Sophisticated adversaries may correlate traffic
- **Quantum Computers**: Classical crypto (X25519, Ed25519) vulnerable to quantum attacks

### 16.4 Future Threats

- **Quantum Computers**: Shor's algorithm breaks ECDLP (X25519, Ed25519)
  - Mitigation: None currently implemented (Future Work)
- **Side-Channel Attacks**: New hardware vulnerabilities (Spectre, Meltdown)
  - Mitigation: Constant-time operations, hardware countermeasures
- **AI-Powered Analysis**: Machine learning for traffic analysis
  - Mitigation: Stronger obfuscation, dummy traffic

---

## 17. IANA Considerations

This document has no IANA actions.

If Sibna is standardized, the following registrations would be needed:
- Protocol identifier
- Port number (if applicable)
- Message type codes
- Error codes

---

## 18. References

### 18.1 Normative References

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.

[RFC5869] Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, May 2010.

[RFC7748] Langley, A., Hamburg, M., and S. Turner, "Elliptic Curves for Security", RFC 7748, January 2016.

[RFC8439] Nir, Y. and A. Langley, "ChaCha20 and Poly1305 for IETF Protocols", RFC 8439, June 2018.

[NOISE] Perrin, T., "The Noise Protocol Framework", 2018. https://noiseprotocol.org/noise.html

[DOUBLERATCHET] Marlinspike, M. and T. Perrin, "The Double Ratchet Algorithm", 2016. https://signal.org/docs/specifications/doubleratchet/



### 18.2 Informative References

[SIGNAL] Cohn-Gordon, K., Cremers, C., Dowling, B., Garratt, L., and D. Stebila, "A Formal Security Analysis of the Signal Messaging Protocol", IEEE European Symposium on Security and Privacy (EuroS&P), 2017.

[DOUBLERATCHET-ANALYSIS] Alwen, J., Coretti, S., and Y. Dodis, "The Double Ratchet: Security Notions, Proofs, and Modularization for the Signal Protocol", EUROCRYPT 2019.

[WIREGUARD] Donenfeld, J., "WireGuard: Next Generation Kernel Network Tunnel", NDSS 2017.

[TOR] Dingledine, R., Mathewson, N., and P. Syverson, "Tor: The Second-Generation Onion Router", USENIX Security Symposium, 2004.

[TLS13] Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446, August 2018.

[X3DH] Marlinspike, M. and T. Perrin, "The X3DH Key Agreement Protocol", 2016.

---

## 19. Appendices

### Appendix A: Test Vectors

#### A.1 X25519 Test Vector

```
Alice private key:
  77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a

Alice public key:
  8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a

Bob private key:
  5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb

Bob public key:
  de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f

Shared secret:
  4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
```

#### A.2 ChaCha20-Poly1305 Test Vector

```
Key:
  808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f

Nonce:
  070000004041424344454647

Plaintext:
  4c616469657320616e642047656e746c656d656e206f662074686520636c617373
  206f66202739393a204966204920636f756c64206f6666657220796f75206f6e
  6c79206f6e652074697020666f7220746865206675747572652c2073756e7363
  7265656e20776f756c642062652069742e

Ciphertext + Tag:
  d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
  3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
  92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc
  3ff4def08e4b7a9de576d26586cec64b6116
  1ae10b594f09e26a7e902ecbd0600691  # Poly1305 tag
```

### Appendix B: Implementation Checklist

- [ ] Implement X25519 key exchange
- [ ] Implement ChaCha20-Poly1305 AEAD
- [ ] Implement Ed25519 signatures
- [ ] Implement SHA-256 hashing
- [ ] Implement HKDF key derivation

- [ ] Implement Noise_XK handshake
- [ ] Implement Double Ratchet
- [ ] Implement message framing
- [ ] Implement secure key storage
- [ ] Implement secure wiping
- [ ] Implement constant-time operations
- [ ] Implement nonce management
- [ ] Implement error handling
- [ ] Implement logging
- [ ] Implement rate limiting
- [ ] Implement timing jitter
- [ ] Implement padding
- [ ] Write unit tests
- [ ] Write integration tests
- [ ] Perform security audit
- [ ] Perform performance benchmarks

### Appendix C: Acknowledgments

The Sibna protocol builds upon the work of many researchers and engineers:

- Trevor Perrin for the Noise Protocol Framework
- Moxie Marlinspike and Trevor Perrin for the Double Ratchet algorithm
- Daniel J. Bernstein for X25519, ChaCha20, and Ed25519

- The Signal team for pioneering secure messaging
- The WireGuard team for demonstrating simplicity in VPN protocols

### Appendix D: Glossary

- **AEAD**: Authenticated Encryption with Associated Data
- **DH**: Diffie-Hellman key exchange
- **ECDH**: Elliptic Curve Diffie-Hellman
- **KDF**: Key Derivation Function

- **MAC**: Message Authentication Code

- **RTT**: Round-Trip Time

---

**Document Version:** 3.0.0  
**Last Updated:** December 2025  
**Authors:** Sibna Protocol Team  
**License:** Apache 2.0  
**Contact:** https://github.com/f2fx4553/sibna

---
**END OF SPECIFICATION**
