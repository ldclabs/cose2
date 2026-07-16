//! Constants for the COSE, CWT and CBOR-tags IANA registries.
//!
//! These mirror the registries maintained by IANA:
//!
//! - [COSE](https://www.iana.org/assignments/cose/cose.xhtml)
//! - [CWT Claims](https://www.iana.org/assignments/cwt/cwt.xhtml)
//! - [CBOR Tags](https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml)
//!
//! All values are plain `i64` constants so they can be used directly as
//! COSE [`Label`](crate::Label)s and map keys.

#![allow(non_upper_case_globals)]

// ----------------------------------------------------------------------------
// Algorithms
// <https://www.iana.org/assignments/cose/cose.xhtml#algorithms>
// ----------------------------------------------------------------------------

/// RSASSA-PKCS1-v1_5 using SHA-1
pub const AlgorithmRS1: i64 = -65535;
/// WalnutDSA signature
pub const AlgorithmWalnutDSA: i64 = -260;
/// RSASSA-PKCS1-v1_5 using SHA-512
pub const AlgorithmRS512: i64 = -259;
/// RSASSA-PKCS1-v1_5 using SHA-384
pub const AlgorithmRS384: i64 = -258;
/// RSASSA-PKCS1-v1_5 using SHA-256
pub const AlgorithmRS256: i64 = -257;
/// ECDSA using secp256k1 curve and SHA-256
pub const AlgorithmES256K: i64 = -47;
/// HSS/LMS hash-based digital signature
pub const AlgorithmHSS_LMS: i64 = -46;
/// SHAKE-256 512-bit Hash Value
pub const AlgorithmSHAKE256: i64 = -45;
/// SHA-2 512-bit Hash
pub const AlgorithmSHA_512: i64 = -44;
/// SHA-2 384-bit Hash
pub const AlgorithmSHA_384: i64 = -43;
/// RSAES-OAEP w/ SHA-512
pub const AlgorithmRSAES_OAEP_SHA_512: i64 = -42;
/// RSAES-OAEP w/ SHA-256
pub const AlgorithmRSAES_OAEP_SHA_256: i64 = -41;
/// RSAES-OAEP w/ SHA-1
pub const AlgorithmRSAES_OAEP_RFC_8017_default: i64 = -40;
/// RSASSA-PSS w/ SHA-512
pub const AlgorithmPS512: i64 = -39;
/// RSASSA-PSS w/ SHA-384
pub const AlgorithmPS384: i64 = -38;
/// RSASSA-PSS w/ SHA-256
pub const AlgorithmPS256: i64 = -37;
/// ECDSA w/ SHA-512
pub const AlgorithmES512: i64 = -36;
/// ECDSA w/ SHA-384
pub const AlgorithmES384: i64 = -35;
/// ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key
pub const AlgorithmECDH_SS_A256KW: i64 = -34;
/// ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key
pub const AlgorithmECDH_SS_A192KW: i64 = -33;
/// ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key
pub const AlgorithmECDH_SS_A128KW: i64 = -32;
/// ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key
pub const AlgorithmECDH_ES_A256KW: i64 = -31;
/// ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key
pub const AlgorithmECDH_ES_A192KW: i64 = -30;
/// ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key
pub const AlgorithmECDH_ES_A128KW: i64 = -29;
/// ECDH SS w/ HKDF - generate key directly
pub const AlgorithmECDH_SS_HKDF_512: i64 = -28;
/// ECDH SS w/ HKDF - generate key directly
pub const AlgorithmECDH_SS_HKDF_256: i64 = -27;
/// ECDH ES w/ HKDF - generate key directly
pub const AlgorithmECDH_ES_HKDF_512: i64 = -26;
/// ECDH ES w/ HKDF - generate key directly
pub const AlgorithmECDH_ES_HKDF_256: i64 = -25;
/// SHAKE-128 256-bit Hash Value
pub const AlgorithmSHAKE128: i64 = -18;
/// SHA-2 512-bit Hash truncated to 256-bits
pub const AlgorithmSHA_512_256: i64 = -17;
/// SHA-2 256-bit Hash
pub const AlgorithmSHA_256: i64 = -16;
/// SHA-2 256-bit Hash truncated to 64-bits
pub const AlgorithmSHA_256_64: i64 = -15;
/// SHA-1 Hash
pub const AlgorithmSHA_1: i64 = -14;
/// Shared secret w/ AES-MAC 256-bit key
pub const AlgorithmDirect_HKDF_AES_256: i64 = -13;
/// Shared secret w/ AES-MAC 128-bit key
pub const AlgorithmDirect_HKDF_AES_128: i64 = -12;
/// Shared secret w/ HKDF and SHA-512
pub const AlgorithmDirect_HKDF_SHA_512: i64 = -11;
/// Shared secret w/ HKDF and SHA-256
pub const AlgorithmDirect_HKDF_SHA_256: i64 = -10;
/// EdDSA
pub const AlgorithmEdDSA: i64 = -8;
/// ECDSA w/ SHA-256
pub const AlgorithmES256: i64 = -7;
/// Direct use of CEK
pub const AlgorithmDirect: i64 = -6;
/// AES Key Wrap w/ 256-bit key
pub const AlgorithmA256KW: i64 = -5;
/// AES Key Wrap w/ 192-bit key
pub const AlgorithmA192KW: i64 = -4;
/// AES Key Wrap w/ 128-bit key
pub const AlgorithmA128KW: i64 = -3;
/// Reserved
pub const AlgorithmReserved: i64 = 0;
/// AES-GCM mode w/ 128-bit key, 128-bit tag
pub const AlgorithmA128GCM: i64 = 1;
/// AES-GCM mode w/ 192-bit key, 128-bit tag
pub const AlgorithmA192GCM: i64 = 2;
/// AES-GCM mode w/ 256-bit key, 128-bit tag
pub const AlgorithmA256GCM: i64 = 3;
/// HMAC w/ SHA-256 truncated to 64 bits
pub const AlgorithmHMAC_256_64: i64 = 4;
/// HMAC w/ SHA-256
pub const AlgorithmHMAC_256_256: i64 = 5;
/// HMAC w/ SHA-384
pub const AlgorithmHMAC_384_384: i64 = 6;
/// HMAC w/ SHA-512
pub const AlgorithmHMAC_512_512: i64 = 7;
/// AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce
pub const AlgorithmAES_CCM_16_64_128: i64 = 10;
/// AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce
pub const AlgorithmAES_CCM_16_64_256: i64 = 11;
/// AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce
pub const AlgorithmAES_CCM_64_64_128: i64 = 12;
/// AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce
pub const AlgorithmAES_CCM_64_64_256: i64 = 13;
/// AES-MAC 128-bit key, 64-bit tag
pub const AlgorithmAES_MAC_128_64: i64 = 14;
/// AES-MAC 256-bit key, 64-bit tag
pub const AlgorithmAES_MAC_256_64: i64 = 15;
/// ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag
pub const AlgorithmChaCha20Poly1305: i64 = 24;
/// AES-MAC 128-bit key, 128-bit tag
pub const AlgorithmAES_MAC_128_128: i64 = 25;
/// AES-MAC 256-bit key, 128-bit tag
pub const AlgorithmAES_MAC_256_128: i64 = 26;
/// AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce
pub const AlgorithmAES_CCM_16_128_128: i64 = 30;
/// AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce
pub const AlgorithmAES_CCM_16_128_256: i64 = 31;
/// AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce
pub const AlgorithmAES_CCM_64_128_128: i64 = 32;
/// AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce
pub const AlgorithmAES_CCM_64_128_256: i64 = 33;
/// For doing IV generation for symmetric algorithms.
pub const AlgorithmIV_GENERATION: i64 = 34;

// ----------------------------------------------------------------------------
// Header parameters
// <https://www.iana.org/assignments/cose/cose.xhtml#header-parameters>
// ----------------------------------------------------------------------------

/// Reserved
pub const HeaderParameterReserved: i64 = 0;
/// Cryptographic algorithm to use (int / tstr). Protected header parameter.
pub const HeaderParameterAlg: i64 = 1;
/// Critical headers to be understood (`[+ label]`). Protected header parameter.
pub const HeaderParameterCrit: i64 = 2;
/// Content type of the payload (tstr / uint).
pub const HeaderParameterContentType: i64 = 3;
/// Key identifier (bstr).
pub const HeaderParameterKid: i64 = 4;
/// Full Initialization Vector (bstr).
pub const HeaderParameterIV: i64 = 5;
/// Partial Initialization Vector (bstr).
pub const HeaderParameterPartialIV: i64 = 6;
/// CBOR-encoded signature structure.
pub const HeaderParameterCounterSignature: i64 = 7;
/// Counter signature with implied signer and headers (bstr).
pub const HeaderParameterCounterSignature0: i64 = 9;
/// Identifies the context for the key identifier (bstr).
pub const HeaderParameterKidContext: i64 = 10;
/// V2 countersignature attribute.
pub const HeaderParameterCountersignatureV2: i64 = 11;
/// V2 Abbreviated Countersignature.
pub const HeaderParameterCountersignature0V2: i64 = 12;
/// An unordered bag of X.509 certificates (COSE_X509).
pub const HeaderParameterX5Bag: i64 = 32;
/// An ordered chain of X.509 certificates (COSE_X509).
pub const HeaderParameterX5Chain: i64 = 33;
/// Hash of an X.509 certificate (COSE_CertHash).
pub const HeaderParameterX5T: i64 = 34;
/// URI pointing to an X.509 certificate (uri).
pub const HeaderParameterX5U: i64 = 35;
/// Challenge Nonce (bstr).
pub const HeaderParameterCuphNonce: i64 = 256;
/// Public Key (array).
pub const HeaderParameterCuphOwnerPubKey: i64 = 257;

// ----------------------------------------------------------------------------
// Header algorithm parameters
// <https://www.iana.org/assignments/cose/cose.xhtml#header-algorithm-parameters>
// ----------------------------------------------------------------------------

/// static key X.509 certificate chain (COSE_X509).
pub const HeaderAlgorithmParameterX5ChainSender: i64 = -29;
/// URI for the sender's X.509 certificate (uri).
pub const HeaderAlgorithmParameterX5USender: i64 = -28;
/// Thumbprint for the sender's X.509 certificate (COSE_CertHash).
pub const HeaderAlgorithmParameterX5TSender: i64 = -27;
/// Party V other provided information (bstr).
pub const HeaderAlgorithmParameterPartyVOther: i64 = -26;
/// Party V provided nonce (bstr / int).
pub const HeaderAlgorithmParameterPartyVNonce: i64 = -25;
/// Party V identity information (bstr).
pub const HeaderAlgorithmParameterPartyVIdentity: i64 = -24;
/// Party U other provided information (bstr).
pub const HeaderAlgorithmParameterPartyUOther: i64 = -23;
/// Party U provided nonce (bstr / int).
pub const HeaderAlgorithmParameterPartyUNonce: i64 = -22;
/// Party U identity information (bstr).
pub const HeaderAlgorithmParameterPartyUIdentity: i64 = -21;
/// Random salt (bstr).
pub const HeaderAlgorithmParameterSalt: i64 = -20;
/// Static public key identifier for the sender (bstr).
pub const HeaderAlgorithmParameterStaticKeyId: i64 = -3;
/// Static public key for the sender (COSE_Key).
pub const HeaderAlgorithmParameterStaticKey: i64 = -2;
/// Ephemeral public key for the sender (COSE_Key).
pub const HeaderAlgorithmParameterEphemeralKey: i64 = -1;

// ----------------------------------------------------------------------------
// Key common parameters
// <https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters>
// ----------------------------------------------------------------------------

/// Reserved value.
pub const KeyParameterReserved: i64 = 0;
/// Identification of the key type (tstr / int).
pub const KeyParameterKty: i64 = 1;
/// Key identification value - match to kid in message (bstr).
pub const KeyParameterKid: i64 = 2;
/// Key usage restriction to this algorithm (tstr / int).
pub const KeyParameterAlg: i64 = 3;
/// Restrict set of permissible operations (`[+ (tstr / int)]`).
pub const KeyParameterKeyOps: i64 = 4;
/// Base IV to be XORed with Partial IVs (bstr).
pub const KeyParameterBaseIV: i64 = 5;

// ----------------------------------------------------------------------------
// Key types
// <https://www.iana.org/assignments/cose/cose.xhtml#key-type>
// ----------------------------------------------------------------------------

/// This value is reserved.
pub const KeyTypeReserved: i64 = 0;
/// Octet Key Pair.
pub const KeyTypeOKP: i64 = 1;
/// Elliptic Curve Keys w/ x- and y-coordinate pair.
pub const KeyTypeEC2: i64 = 2;
/// RSA Key.
pub const KeyTypeRSA: i64 = 3;
/// Symmetric Keys.
pub const KeyTypeSymmetric: i64 = 4;
/// Public key for HSS/LMS hash-based digital signature.
pub const KeyTypeHSS_LMS: i64 = 5;
/// WalnutDSA public key.
pub const KeyTypeWalnutDSA: i64 = 6;

// ----------------------------------------------------------------------------
// Key type parameters: OKP
// ----------------------------------------------------------------------------

/// EC identifier - "COSE Elliptic Curves" registry (tstr / int).
pub const OKPKeyParameterCrv: i64 = -1;
/// x-coordinate (bstr).
pub const OKPKeyParameterX: i64 = -2;
/// Private key (bstr).
pub const OKPKeyParameterD: i64 = -4;

// ----------------------------------------------------------------------------
// Key type parameters: EC2
// ----------------------------------------------------------------------------

/// EC identifier - "COSE Elliptic Curves" registry (tstr / int).
pub const EC2KeyParameterCrv: i64 = -1;
/// Public Key x-coordinate (bstr).
pub const EC2KeyParameterX: i64 = -2;
/// y-coordinate (bstr / bool).
pub const EC2KeyParameterY: i64 = -3;
/// Private key (bstr).
pub const EC2KeyParameterD: i64 = -4;

// ----------------------------------------------------------------------------
// Key type parameters: RSA
// ----------------------------------------------------------------------------

/// The RSA modulus n (bstr).
pub const RSAKeyParameterN: i64 = -1;
/// The RSA public exponent e (bstr).
pub const RSAKeyParameterE: i64 = -2;
/// The RSA private exponent d (bstr).
pub const RSAKeyParameterD: i64 = -3;
/// The prime factor p of n (bstr).
pub const RSAKeyParameterP: i64 = -4;
/// The prime factor q of n (bstr).
pub const RSAKeyParameterQ: i64 = -5;
/// dP is d mod (p - 1) (bstr).
pub const RSAKeyParameterDP: i64 = -6;
/// dQ is d mod (q - 1) (bstr).
pub const RSAKeyParameterDQ: i64 = -7;
/// qInv is the CRT coefficient q^(-1) mod p (bstr).
pub const RSAKeyParameterQInv: i64 = -8;
/// Other prime infos, an array.
pub const RSAKeyParameterOther: i64 = -9;
/// a prime factor r_i of n, where i >= 3 (bstr).
pub const RSAKeyParameterRI: i64 = -10;
/// d_i = d mod (r_i - 1) (bstr).
pub const RSAKeyParameterDI: i64 = -11;
/// The CRT coefficient t_i = (r_1 * r_2 * ... * r_(i-1))^(-1) mod r_i (bstr).
pub const RSAKeyParameterTI: i64 = -12;

// ----------------------------------------------------------------------------
// Key type parameters: Symmetric
// ----------------------------------------------------------------------------

/// Key Value (bstr).
pub const SymmetricKeyParameterK: i64 = -1;

// ----------------------------------------------------------------------------
// Key type parameters: HSS_LMS
// ----------------------------------------------------------------------------

/// Public key for HSS/LMS hash-based digital signature (bstr).
pub const HSS_LMSKeyParameterPub: i64 = -1;

// ----------------------------------------------------------------------------
// Key type parameters: WalnutDSA
// ----------------------------------------------------------------------------

/// Group and Matrix (NxN) size (uint).
pub const WalnutDSAKeyParameterN: i64 = -1;
/// Finite field F_q (uint).
pub const WalnutDSAKeyParameterQ: i64 = -2;
/// List of T-values, entries in F_q (array of uint).
pub const WalnutDSAKeyParameterTValues: i64 = -3;
/// NxN Matrix of entries in F_q in column-major form (array of array of uint).
pub const WalnutDSAKeyParameterMatrix1: i64 = -4;
/// Permutation associated with matrix 1 (array of uint).
pub const WalnutDSAKeyParameterPermutation1: i64 = -5;
/// NxN Matrix of entries in F_q in column-major form (array of array of uint).
pub const WalnutDSAKeyParameterMatrix2: i64 = -6;

// ----------------------------------------------------------------------------
// Elliptic curves
// <https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves>
// ----------------------------------------------------------------------------

/// Reserved.
pub const EllipticCurveReserved: i64 = 0;
/// EC2: NIST P-256 also known as secp256r1.
pub const EllipticCurveP_256: i64 = 1;
/// EC2: NIST P-384 also known as secp384r1.
pub const EllipticCurveP_384: i64 = 2;
/// EC2: NIST P-521 also known as secp521r1.
pub const EllipticCurveP_521: i64 = 3;
/// OKP: X25519 for use w/ ECDH only.
pub const EllipticCurveX25519: i64 = 4;
/// OKP: X448 for use w/ ECDH only.
pub const EllipticCurveX448: i64 = 5;
/// OKP: Ed25519 for use w/ EdDSA only.
pub const EllipticCurveEd25519: i64 = 6;
/// OKP: Ed448 for use w/ EdDSA only.
pub const EllipticCurveEd448: i64 = 7;
/// EC2: SECG secp256k1 curve.
pub const EllipticCurveSecp256k1: i64 = 8;

// ----------------------------------------------------------------------------
// Key operation values
// <https://datatracker.ietf.org/doc/html/rfc9052#name-key-operation-values>
// ----------------------------------------------------------------------------

/// Key is used to create signatures. Requires private key fields.
pub const KeyOperationSign: i64 = 1;
/// Key is used for verification of signatures.
pub const KeyOperationVerify: i64 = 2;
/// Key is used for key transport encryption.
pub const KeyOperationEncrypt: i64 = 3;
/// Key is used for key transport decryption. Requires private key fields.
pub const KeyOperationDecrypt: i64 = 4;
/// Key is used for key wrap encryption.
pub const KeyOperationWrapKey: i64 = 5;
/// Key is used for key wrap decryption. Requires private key fields.
pub const KeyOperationUnwrapKey: i64 = 6;
/// Key is used for deriving keys. Requires private key fields.
pub const KeyOperationDeriveKey: i64 = 7;
/// Key is used for deriving bits not to be used as a key. Requires private key fields.
pub const KeyOperationDeriveBits: i64 = 8;
/// Key is used for creating MACs.
pub const KeyOperationMacCreate: i64 = 9;
/// Key is used for validating MACs.
pub const KeyOperationMacVerify: i64 = 10;

// ----------------------------------------------------------------------------
// CWT claims
// <https://www.iana.org/assignments/cwt/cwt.xhtml>
// ----------------------------------------------------------------------------

/// Health certificate ("hcert": map).
pub const CWTClaimHCert: i64 = -260;
/// Challenge nonce ("EUPHNonce": bstr).
pub const CWTClaimEUPHNonce: i64 = -259;
/// Signing prefix for multi-app restricted operating environment ("EATMAROEPrefix": bstr).
pub const CWTClaimEATMAROEPrefix: i64 = -258;
/// FIDO Device Onboarding EAT ("EAT-FDO": array).
pub const CWTClaimEATFDO: i64 = -257;
/// Reserved value.
pub const CWTClaimReserved: i64 = 0;
/// Issuer ("iss": tstr).
pub const CWTClaimIss: i64 = 1;
/// Subject ("sub": tstr).
pub const CWTClaimSub: i64 = 2;
/// Audience ("aud": tstr).
pub const CWTClaimAud: i64 = 3;
/// Expiration Time, as seconds since UNIX epoch ("exp": int/float).
pub const CWTClaimExp: i64 = 4;
/// Not Before, as seconds since UNIX epoch ("nbf": int/float).
pub const CWTClaimNbf: i64 = 5;
/// Issued at, as seconds since UNIX epoch ("iat": int/float).
pub const CWTClaimIat: i64 = 6;
/// CWT ID ("cti": bstr).
pub const CWTClaimCti: i64 = 7;
/// Confirmation ("cnf": map).
pub const CWTClaimCnf: i64 = 8;
/// Scope of an access token ("scope": bstr/tstr).
pub const CWTClaimScope: i64 = 9;
/// Nonce ("nonce": bstr).
pub const CWTClaimNonce: i64 = 10;
/// The ACE profile a token is supposed to be used with ("ace_profile": int).
pub const CWTClaimACEProfile: i64 = 38;
/// The client-nonce sent to the AS by the RS via the client ("cnonce": bstr).
pub const CWTClaimCNonce: i64 = 39;
/// The expiration time of a token measured from when it was received at the RS in seconds ("exi": int).
pub const CWTClaimExi: i64 = 40;
/// The Universal Entity ID ("ueid": bstr).
pub const CWTClaimUEID: i64 = 256;
/// Semipermanent UEIDs ("sueids": map).
pub const CWTClaimSUEIDs: i64 = 257;
/// Hardware OEM ID ("oemid": bstr/int).
pub const CWTClaimOEMID: i64 = 258;
/// Model identifier for hardware ("hwmodel": bstr).
pub const CWTClaimHWModel: i64 = 259;
/// Hardware Version Identifier ("hwversion": array).
pub const CWTClaimHWVersion: i64 = 260;
/// Uptime since boot ("uptime": uint).
pub const CWTClaimUptime: i64 = 261;
/// Indicates whether the software booted was OEM authorized ("oemboot": bool).
pub const CWTClaimOEMBoot: i64 = 262;
/// Indicate status of debug facilities ("dbgstat": int).
pub const CWTClaimDebugStatus: i64 = 263;
/// The geographic location ("location": map).
pub const CWTClaimLocation: i64 = 264;
/// Indicates the EAT profile followed ("eat_profile": uri/oid).
pub const CWTClaimProfile: i64 = 265;
/// The section containing submodules ("submods": map).
pub const CWTClaimSubmodules: i64 = 266;
/// The number of times the entity or submodule has been booted ("bootcount": uint).
pub const CWTClaimBootCount: i64 = 267;
/// Identifies a boot cycle ("bootseed": bstr).
pub const CWTClaimBootSeed: i64 = 268;
/// PSA Client ID (signed integer).
pub const CWTClaimPSAClientID: i64 = 2394;
/// PSA Security Lifecycle (unsigned integer).
pub const CWTClaimPSASecurityLifecycle: i64 = 2395;
/// PSA Implementation ID (bstr).
pub const CWTClaimPSAImplementationID: i64 = 2396;
// Claim key 2397 is unassigned: the final PSA token spec (RFC 9783) dropped
// its draft-era boot-seed claim in favor of the shared EAT `bootseed` (268),
// exposed above as `CWTClaimBootSeed`.
/// PSA Certification Reference (tstr).
pub const CWTClaimPSACertificationReference: i64 = 2398;
/// PSA Software Components (array).
pub const CWTClaimPSASoftwareComponents: i64 = 2399;
/// PSA Verification Service Indicator (tstr).
pub const CWTClaimPSAVerificationServiceIndicator: i64 = 2400;

// ----------------------------------------------------------------------------
// CBOR tags for COSE structures
// <https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml>
// ----------------------------------------------------------------------------

/// COSE Single Recipient Encrypted Data Object.
pub const CBORTagCOSEEncrypt0: u64 = 16;
/// COSE Mac w/o Recipients Object.
pub const CBORTagCOSEMac0: u64 = 17;
/// COSE Single Signer Data Object.
pub const CBORTagCOSESign1: u64 = 18;
/// CBOR Web Token (CWT).
pub const CBORTagCWT: u64 = 61;
/// COSE Encrypted Data Object.
pub const CBORTagCOSEEncrypt: u64 = 96;
/// COSE MACed Data Object.
pub const CBORTagCOSEMac: u64 = 97;
/// COSE Signed Data Object.
pub const CBORTagCOSESign: u64 = 98;
