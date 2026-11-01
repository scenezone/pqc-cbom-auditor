from dataclasses import dataclass

@dataclass(frozen=True)
class SignatureRule:
    rule_id: str
    language: str
    library_name: str
    imported_symbol: str
    pattern: str
    algorithm: str
    crypto_operation: str
    cryptographic_purpose: str
    evidence_type: str = "api_call"
    detection_confidence: str = "medium"

SIGNATURE_RULES = [
    # Python - Asymmetric
    SignatureRule("PY-RSA-GEN","python","cryptography","rsa.generate_private_key",r"(rsa\.generate_private_key|RSA\.generate)","RSA","key_generation","digital_signature"),
    SignatureRule("PY-RSA-ENC","python","cryptography","rsa.encrypt",r"(rsa\.encrypt|RSAOAEP|PKCS1v15|PKCS1_OAEP)","RSA","encryption","confidentiality"),
    SignatureRule("PY-RSA-SIGN","python","cryptography","rsa.sign",r"(rsa\.sign|PSS|PKCS1_v1_5)","RSA","digital_signature","authenticity"),
    SignatureRule("PY-ECDSA","python","cryptography","ec.generate_private_key",r"(ec\.generate_private_key|SECP256R1|SECP384R1|SECP521R1|prime256v1|secp256k1|ec\.ECDSA|DSS\.new)","ECDSA","digital_signature","authenticity"),
    SignatureRule("PY-ECDH","python","cryptography","ec.ECDH",r"(ec\.ECDH|\bECDH\b)","ECDH","key_exchange","key_establishment"),
    SignatureRule("PY-X25519","python","cryptography","x25519",r"(X25519PrivateKey|\bX25519\b)","X25519","key_exchange","key_establishment"),
    SignatureRule("PY-ED25519","python","cryptography","ed25519",r"(Ed25519PrivateKey|\bEd25519\b)","Ed25519","digital_signature","authenticity"),
    # Python - Symmetric
    SignatureRule("PY-AES","python","cryptography","AES",r"(AES\.new|algorithms\.AES\b|\bAES\b)","AES","encryption","confidentiality"),
    SignatureRule("PY-CHACHA","python","cryptography","ChaCha20",r"(algorithms\.ChaCha20|ChaCha20\.new|ChaCha20Poly1305)","ChaCha20","encryption","confidentiality"),
    SignatureRule("PY-DES","python","cryptography","DES",r"(algorithms\.TripleDES|DES\.new|DES3\.new|\bTripleDES\b|\bDES\b)","DES","encryption","confidentiality"),
    SignatureRule("PY-BLOWFISH","python","cryptography","Blowfish",r"(algorithms\.Blowfish|Blowfish\.new|\bBlowfish\b)","Blowfish","encryption","confidentiality"),
    # Python - Hashes
    SignatureRule("PY-HASHES-SHA256","python","hashlib","sha256",r"(hashes\.SHA256|hashlib\.sha256|\bsha256\b)","SHA-256","hashing","integrity"),
    SignatureRule("PY-HASHES-SHA512","python","hashlib","sha512",r"(hashes\.SHA512|hashlib\.sha512|\bsha512\b)","SHA-512","hashing","integrity"),
    SignatureRule("PY-HASHES-SHA384","python","hashlib","sha384",r"(hashes\.SHA384|hashlib\.sha384|\bsha384\b)","SHA-384","hashing","integrity"),
    SignatureRule("PY-HASHES-SHA224","python","hashlib","sha224",r"(hashes\.SHA224|hashlib\.sha224|\bsha224\b)","SHA-224","hashing","integrity"),
    SignatureRule("PY-HASHES-SHA3","python","hashlib","sha3_256",r"(hashes\.SHA3_256|hashes\.SHA3_512|hashlib\.sha3_256|hashlib\.sha3_512|\bsha3_256\b)","SHA3-256","hashing","integrity"),
    SignatureRule("PY-HASHES-MD5","python","hashlib","md5",r"(hashes\.MD5|hashlib\.md5|\bmd5\b)","MD5","hashing","integrity"),
    SignatureRule("PY-HASHES-SHA1","python","hashlib","sha1",r"(hashes\.SHA1|hashlib\.sha1|\bsha1\b)","SHA-1","hashing","integrity"),
    SignatureRule("PY-HASHES-HASH","python","cryptography","hashes.Hash",r"hashes\.Hash\s*\(","SHA-256","hashing","integrity"),
    SignatureRule("PY-HASHLIB-NEW","python","hashlib","hashlib.new",r"hashlib\.new\s*\(","Hash","hashing","integrity"),
    # Python - MAC & Auth & Passwords
    SignatureRule("PY-HMAC","python","hmac","hmac",r"(hmac\.new|hmac\.HMAC|HMAC\()","HMAC","mac","integrity"),
    SignatureRule("PY-JWT","python","pyjwt","jwt.encode",r"(jwt\.encode|jwt\.decode)","RSA","digital_signature","authenticity"),
    SignatureRule("PY-BCRYPT","python","bcrypt","bcrypt.hashpw",r"bcrypt\.(hashpw|gensalt|checkpw)","bcrypt","key_derivation","integrity"),
    SignatureRule("PY-SSL","python","ssl","ssl.create_default_context",r"ssl\.(create_default_context|wrap_socket)","TLS","protocol","transport_security"),
    # Python - PQC
    SignatureRule("PY-MLKEM","python","pqcrypto","ML-KEM",r"(ML[-_]?KEM|kyber)","ML-KEM","key_encapsulation","key_establishment"),
    SignatureRule("PY-MLDSA","python","pqcrypto","ML-DSA",r"(ML[-_]?DSA|dilithium)","ML-DSA","digital_signature","authenticity"),
    SignatureRule("PY-SLHDSA","python","pqcrypto","SLH-DSA",r"(SLH[-_]?DSA|sphincs)","SLH-DSA","digital_signature","authenticity"),

    # JavaScript - Node & WebCrypto & npm libraries
    SignatureRule("JS-NODE-RSA-GEN","javascript","node:crypto","generateKeyPair",r"(generateKeyPair|generateKeyPairSync)\s*\(\s*['\"]rsa['\"]","RSA","key_generation","digital_signature"),
    SignatureRule("JS-NODE-EC-GEN","javascript","node:crypto","generateKeyPair",r"(generateKeyPair|generateKeyPairSync)\s*\(\s*['\"](ec|ed25519|x25519)['\"]","ECDSA","key_generation","digital_signature"),
    SignatureRule("JS-NODE-CIPHER","javascript","node:crypto","createCipheriv",r"(createCipheriv|createDecipheriv|createCipher|createDecipher)\s*\(","AES","encryption","confidentiality"),
    SignatureRule("JS-NODE-HASH","javascript","node:crypto","createHash",r"createHash\s*\(\s*['\"]([^'\"]+)['\"]","SHA","hashing","integrity"),
    SignatureRule("JS-NODE-HMAC","javascript","node:crypto","createHmac",r"createHmac\s*\(\s*['\"]([^'\"]+)['\"]","HMAC","mac","integrity"),
    SignatureRule("JS-NODE-SIGN","javascript","node:crypto","createSign",r"(createSign|createVerify)\s*\(","RSA","digital_signature","authenticity"),
    SignatureRule("JS-NODE-DIFFIE","javascript","node:crypto","createDiffieHellman",r"(createDiffieHellman|createECDH)\s*\(","ECDH","key_exchange","key_establishment"),
    SignatureRule("JS-WEB-SUBTLE","javascript","Web Crypto API","subtle",r"crypto\.subtle\.(generateKey|encrypt|decrypt|sign|verify|digest|deriveKey|deriveBits)","Unknown","crypto_operation","multiple"),
    SignatureRule("JS-WEB-AES","javascript","Web Crypto API","AES-GCM",r"['\"]AES-(GCM|CBC|CTR)['\"]","AES","encryption","confidentiality"),
    SignatureRule("JS-WEB-RSA","javascript","Web Crypto API","RSA-OAEP",r"['\"](RSA-OAEP|RSASSA-PKCS1-v1_5|RSA-PSS)['\"]","RSA","encryption","confidentiality"),
    SignatureRule("JS-WEB-ECDSA","javascript","Web Crypto API","ECDSA",r"['\"](ECDSA|P-256|P-384|P-521)['\"]","ECDSA","digital_signature","authenticity"),
    SignatureRule("JS-WEB-ECDH","javascript","Web Crypto API","ECDH",r"['\"]ECDH['\"]","ECDH","key_exchange","key_establishment"),
    SignatureRule("JS-CRYPTOJS-AES","javascript","crypto-js","CryptoJS.AES",r"CryptoJS\.AES\.(encrypt|decrypt)","AES","encryption","confidentiality"),
    SignatureRule("JS-CRYPTOJS-HASH","javascript","crypto-js","CryptoJS.Hash",r"CryptoJS\.(SHA256|SHA512|SHA3|SHA1|MD5|HmacSHA256|HmacSHA512)\b","SHA-256","hashing","integrity"),
    SignatureRule("JS-JWT","javascript","jsonwebtoken","jwt.sign",r"jwt\.(sign|verify|decode)\s*\(","RSA","digital_signature","authenticity"),
    SignatureRule("JS-BCRYPT","javascript","bcrypt","bcrypt.hash",r"bcrypt\.(hash|hashSync|compare|compareSync|genSalt)\s*\(","bcrypt","key_derivation","integrity"),
    SignatureRule("JS-FORGE","javascript","node-forge","forge.pki",r"forge\.(pki|cipher|md)\b","RSA","crypto_operation","multiple"),
    SignatureRule("JS-PQC","javascript","pqc","ML-KEM",r"(ML[-_]?KEM|ML[-_]?DSA|SLH[-_]?DSA|kyber|dilithium)","ML-KEM","key_encapsulation","key_establishment"),

    # TypeScript - Mirrors JavaScript rules
    SignatureRule("TS-NODE-RSA-GEN","typescript","node:crypto","generateKeyPair",r"(generateKeyPair|generateKeyPairSync)\s*\(\s*['\"]rsa['\"]","RSA","key_generation","digital_signature"),
    SignatureRule("TS-NODE-EC-GEN","typescript","node:crypto","generateKeyPair",r"(generateKeyPair|generateKeyPairSync)\s*\(\s*['\"](ec|ed25519|x25519)['\"]","ECDSA","key_generation","digital_signature"),
    SignatureRule("TS-NODE-CIPHER","typescript","node:crypto","createCipheriv",r"(createCipheriv|createDecipheriv|createCipher|createDecipher)\s*\(","AES","encryption","confidentiality"),
    SignatureRule("TS-NODE-HASH","typescript","node:crypto","createHash",r"createHash\s*\(\s*['\"]([^'\"]+)['\"]","SHA","hashing","integrity"),
    SignatureRule("TS-NODE-HMAC","typescript","node:crypto","createHmac",r"createHmac\s*\(\s*['\"]([^'\"]+)['\"]","HMAC","mac","integrity"),
    SignatureRule("TS-NODE-SIGN","typescript","node:crypto","createSign",r"(createSign|createVerify)\s*\(","RSA","digital_signature","authenticity"),
    SignatureRule("TS-NODE-DIFFIE","typescript","node:crypto","createDiffieHellman",r"(createDiffieHellman|createECDH)\s*\(","ECDH","key_exchange","key_establishment"),
    SignatureRule("TS-WEB-SUBTLE","typescript","Web Crypto API","subtle",r"crypto\.subtle\.(generateKey|encrypt|decrypt|sign|verify|digest|deriveKey|deriveBits)","Unknown","crypto_operation","multiple"),
    SignatureRule("TS-WEB-AES","typescript","Web Crypto API","AES-GCM",r"['\"]AES-(GCM|CBC|CTR)['\"]","AES","encryption","confidentiality"),
    SignatureRule("TS-WEB-RSA","typescript","Web Crypto API","RSA-OAEP",r"['\"](RSA-OAEP|RSASSA-PKCS1-v1_5|RSA-PSS)['\"]","RSA","encryption","confidentiality"),
    SignatureRule("TS-WEB-ECDSA","typescript","Web Crypto API","ECDSA",r"['\"](ECDSA|P-256|P-384|P-521)['\"]","ECDSA","digital_signature","authenticity"),
    SignatureRule("TS-WEB-ECDH","typescript","Web Crypto API","ECDH",r"['\"]ECDH['\"]","ECDH","key_exchange","key_establishment"),
    SignatureRule("TS-CRYPTOJS-AES","typescript","crypto-js","CryptoJS.AES",r"CryptoJS\.AES\.(encrypt|decrypt)","AES","encryption","confidentiality"),
    SignatureRule("TS-CRYPTOJS-HASH","typescript","crypto-js","CryptoJS.Hash",r"CryptoJS\.(SHA256|SHA512|SHA3|SHA1|MD5|HmacSHA256|HmacSHA512)\b","SHA-256","hashing","integrity"),
    SignatureRule("TS-JWT","typescript","jsonwebtoken","jwt.sign",r"jwt\.(sign|verify|decode)\s*\(","RSA","digital_signature","authenticity"),
    SignatureRule("TS-BCRYPT","typescript","bcrypt","bcrypt.hash",r"bcrypt\.(hash|hashSync|compare|compareSync|genSalt)\s*\(","bcrypt","key_derivation","integrity"),
    SignatureRule("TS-FORGE","typescript","node-forge","forge.pki",r"forge\.(pki|cipher|md)\b","RSA","crypto_operation","multiple"),
    SignatureRule("TS-PQC","typescript","pqc","ML-KEM",r"(ML[-_]?KEM|ML[-_]?DSA|SLH[-_]?DSA|kyber|dilithium)","ML-KEM","key_encapsulation","key_establishment"),

    # Java - JCA / JCE & Bouncy Castle
    SignatureRule("JAVA-CIPHER","java","javax.crypto","Cipher.getInstance",r"Cipher\.getInstance\s*\(\s*['\"]([^'\"]+)['\"]","AES","encryption","confidentiality"),
    SignatureRule("JAVA-AES","java","javax.crypto","AES",r"['\"]AES[/-][^'\"]*['\"]","AES","encryption","confidentiality"),
    SignatureRule("JAVA-RSA","java","java.security","KeyPairGenerator",r"KeyPairGenerator\.getInstance\s*\(\s*['\"]RSA['\"]","RSA","key_generation","digital_signature"),
    SignatureRule("JAVA-EC","java","java.security","KeyPairGenerator",r"KeyPairGenerator\.getInstance\s*\(\s*['\"](EC|ECDSA)['\"]","ECDSA","key_generation","digital_signature"),
    SignatureRule("JAVA-SIGNATURE","java","java.security","Signature",r"Signature\.getInstance\s*\(\s*['\"]([^'\"]+)['\"]","ECDSA","digital_signature","authenticity"),
    SignatureRule("JAVA-DIGEST","java","java.security","MessageDigest",r"MessageDigest\.getInstance\s*\(\s*['\"]([^'\"]+)['\"]","SHA","hashing","integrity"),
    SignatureRule("JAVA-MAC","java","javax.crypto","Mac",r"Mac\.getInstance\s*\(\s*['\"]([^'\"]+)['\"]","HMAC","mac","integrity"),
    SignatureRule("JAVA-KEY-AGREEMENT","java","javax.crypto","KeyAgreement",r"KeyAgreement\.getInstance\s*\(\s*['\"]([^'\"]+)['\"]","ECDH","key_exchange","key_establishment"),
    SignatureRule("JAVA-KEY-GEN","java","javax.crypto","KeyGenerator",r"KeyGenerator\.getInstance\s*\(\s*['\"]([^'\"]+)['\"]","AES","key_generation","confidentiality"),
    SignatureRule("JAVA-PQC","java","bouncycastle","PQC",r"(ML-KEM|ML-DSA|SLH-DSA|Kyber|Dilithium|BouncyCastleProvider)","ML-KEM","key_encapsulation","key_establishment"),

    # Go - Standard crypto & x/crypto
    SignatureRule("GO-RSA","go","crypto/rsa","rsa.GenerateKey",r"rsa\.(GenerateKey|EncryptOAEP|EncryptPKCS1v15|SignPKCS1v15|SignPSS|VerifyPKCS1v15|VerifyPSS)","RSA","multiple","multiple"),
    SignatureRule("GO-ECDSA","go","crypto/ecdsa","ecdsa",r"ecdsa\.(GenerateKey|Sign|Verify|SignASN1|VerifyASN1)","ECDSA","digital_signature","authenticity"),
    SignatureRule("GO-ECDH","go","crypto/ecdh","ecdh",r"ecdh\.(X25519|P256|P384|P521)","ECDH","key_exchange","key_establishment"),
    SignatureRule("GO-ED25519","go","crypto/ed25519","ed25519",r"ed25519\.(GenerateKey|Sign|Verify)","Ed25519","digital_signature","authenticity"),
    SignatureRule("GO-AES","go","crypto/aes","aes.NewCipher",r"aes\.NewCipher","AES","encryption","confidentiality"),
    SignatureRule("GO-DES","go","crypto/des","des.NewCipher",r"des\.(NewCipher|NewTripleDESCipher)","DES","encryption","confidentiality"),
    SignatureRule("GO-SHA256","go","crypto/sha256","sha256",r"sha256\.(New|Sum256)","SHA-256","hashing","integrity"),
    SignatureRule("GO-SHA512","go","crypto/sha512","sha512",r"sha512\.(New|Sum512)","SHA-512","hashing","integrity"),
    SignatureRule("GO-SHA1","go","crypto/sha1","sha1",r"sha1\.(New|Sum)","SHA-1","hashing","integrity"),
    SignatureRule("GO-MD5","go","crypto/md5","md5",r"md5\.(New|Sum)","MD5","hashing","integrity"),
    SignatureRule("GO-HMAC","go","crypto/hmac","hmac.New",r"hmac\.New","HMAC","mac","integrity"),
    SignatureRule("GO-TLS","go","crypto/tls","tls.Config",r"tls\.(Config|Dial|Listen|Client|Server)","TLS","protocol","transport_security"),
    SignatureRule("GO-X-CRYPTO","go","golang.org/x/crypto","x/crypto",r"(bcrypt\.GenerateFromPassword|argon2\.IDKey|chacha20poly1305\.New)","bcrypt","key_derivation","integrity"),
    SignatureRule("GO-PQC","go","pqc","mlkem",r"(mlkem|mldsa|slhdsa|kyber|dilithium)","ML-KEM","key_encapsulation","key_establishment"),

    # C and C++ - OpenSSL and common crypto APIs
    SignatureRule("CPP-OPENSSL-RSA","cpp","OpenSSL","RSA_*",r"\bRSA_(?:generate_key_ex|public_encrypt|private_decrypt|sign|verify)\b","RSA","crypto_operation","multiple"),
    SignatureRule("CPP-OPENSSL-CIPHER","cpp","OpenSSL EVP","EVP cipher",r"\bEVP_(?:Encrypt|Decrypt)Init(?:_ex2?)?\s*\(","AES","encryption","confidentiality"),
    SignatureRule("CPP-OPENSSL-DIGEST","cpp","OpenSSL EVP","EVP digest",r"\bEVP_Digest(?:Init|Update|Final)[A-Za-z0-9_]*\s*\(","SHA","hashing","integrity"),
    SignatureRule("CPP-OPENSSL-EC","cpp","OpenSSL","EC/ECDH",r"\b(?:EC_KEY_(?:new|generate_key)|ECDH_compute_key|EVP_PKEY_derive)\s*\(","ECDH","key_exchange","key_establishment"),
    SignatureRule("CPP-OPENSSL-TLS","cpp","OpenSSL","SSL_CTX",r"\b(?:SSL_CTX_new|TLS_client_method|TLS_server_method)\s*\(","TLS","protocol","transport_security"),
    SignatureRule("CPP-PQC","cpp","PQC","PQC API",r"\b(?:ML[-_]?KEM|ML[-_]?DSA|SLH[-_]?DSA|Kyber|Dilithium|SPHINCS)\b","ML-KEM","crypto_operation","multiple"),

    # Rust - RustCrypto, ring, OpenSSL, and common crate APIs
    SignatureRule("RUST-RSA","rust","rsa","RsaPrivateKey/RsaPublicKey",r"\b(?:RsaPrivateKey|RsaPublicKey|rsa::(?:Oaep|Pkcs1v15Sign))\b","RSA","crypto_operation","multiple"),
    SignatureRule("RUST-AES","rust","RustCrypto","AES-GCM",r"\b(?:Aes(?:128|192|256)Gcm|AesGcm|aes_gcm::)\b","AES","encryption","confidentiality"),
    SignatureRule("RUST-HASH","rust","RustCrypto","SHA digest",r"\b(?:Sha(?:1|224|256|384|512)|sha[123]::|Digest::digest)\b","SHA","hashing","integrity"),
    SignatureRule("RUST-ED25519","rust","ed25519-dalek","Ed25519",r"\b(?:ed25519_dalek|Ed25519(Signing|Verifying)Key)\b","Ed25519","digital_signature","authenticity"),
    SignatureRule("RUST-X25519","rust","x25519-dalek","X25519",r"\b(?:x25519_dalek|StaticSecret|EphemeralSecret)\b","X25519","key_exchange","key_establishment"),
    SignatureRule("RUST-RING","rust","ring","ring crypto",r"\bring::(?:signature|aead|agreement)::","Unknown","crypto_operation","multiple"),
    SignatureRule("RUST-PQC","rust","PQC","PQC API",r"\b(?:ml_kem|ml_dsa|slh_dsa|kyber|dilithium|sphincs)\b","ML-KEM","crypto_operation","multiple"),

    # C# and .NET
    SignatureRule("CSHARP-RSA","csharp",".NET Cryptography","RSA",r"\bRSA\.(?:Create|Import|OpenSsl)\s*\(","RSA","crypto_operation","multiple"),
    SignatureRule("CSHARP-ECDSA","csharp",".NET Cryptography","ECDSA",r"\b(?:ECDsa|ECDiffieHellman)\.(?:Create|GenerateKey)\s*\(","ECDSA","crypto_operation","multiple"),
    SignatureRule("CSHARP-AES","csharp",".NET Cryptography","Aes",r"\bAes(?:Gcm|Ccm)?\.Create\s*\(|\bnew\s+AesGcm\s*\(","AES","encryption","confidentiality"),
    SignatureRule("CSHARP-HASH","csharp",".NET Cryptography","HashAlgorithm",r"\b(?:SHA(?:1|256|384|512)|MD5|HMACSHA(?:1|256|384|512))\.Create\s*\(","SHA","hashing","integrity"),
    SignatureRule("CSHARP-TLS","csharp",".NET TLS","SslStream",r"\b(?:SslStream|SslProtocols|Tls12|Tls13)\b","TLS","protocol","transport_security"),

    # PHP and Ruby
    SignatureRule("PHP-OPENSSL","php","OpenSSL","openssl_*",r"\bopenssl_(?:encrypt|decrypt|public_encrypt|private_decrypt|sign|verify|pkey_new)\s*\(","RSA","crypto_operation","multiple"),
    SignatureRule("PHP-HASH","php","PHP hash","hash/hmac",r"\b(?:hash|hash_hmac|hash_init|password_hash)\s*\(","SHA","hashing","integrity"),
    SignatureRule("RUBY-OPENSSL","ruby","OpenSSL","OpenSSL::Cipher",r"\bOpenSSL::(?:Cipher|Digest|PKey|HMAC)\b","AES","crypto_operation","multiple"),
    SignatureRule("RUBY-SECURE-RANDOM","ruby","Ruby OpenSSL","SecureRandom",r"\b(?:SecureRandom|OpenSSL::Random)\b","Unknown","random_generation","key_generation"),

    # Swift and Objective-C CryptoKit / CommonCrypto
    SignatureRule("SWIFT-CRYPTOKIT-AES","swift","CryptoKit","AES.GCM",r"\b(?:AES\.(?:GCM|CBC)|CryptoKit\.AES)\b","AES","encryption","confidentiality"),
    SignatureRule("SWIFT-CRYPTOKIT-HASH","swift","CryptoKit","SHA",r"\b(?:SHA256|SHA384|SHA512|Insecure\.SHA1)\b","SHA","hashing","integrity"),
    SignatureRule("SWIFT-CRYPTOKIT-EC","swift","CryptoKit","P256/P384/P521",r"\b(?:P256|P384|P521|Curve25519)\b","ECDSA","crypto_operation","multiple"),
    SignatureRule("SWIFT-COMMONCRYPTO","swift","CommonCrypto","CCCrypt",r"\b(?:CCCrypt|CC_SHA(?:1|256|384|512)|CCHmac)\s*\(?","AES","crypto_operation","multiple"),

    # Shell commands and SQL pgcrypto
    SignatureRule("SHELL-OPENSSL","shell","OpenSSL CLI","openssl",r"\bopenssl\s+(?:enc|dgst|genpkey|pkeyutl|req|s_client|s_server)\b","TLS","crypto_operation","multiple"),
    SignatureRule("SHELL-GPG","shell","GnuPG","gpg",r"\bgpg\s+.*(?:--encrypt|--decrypt|--sign|--verify|--gen-key)","RSA","crypto_operation","multiple"),
    SignatureRule("SQL-PGCRYPTO","sql","PostgreSQL pgcrypto","pgcrypto",r"\b(?:pgp_(?:sym|pub)_encrypt|pgp_(?:sym|pub)_decrypt|digest|hmac|crypt|gen_random_bytes)\s*\(","Cryptographic function","crypto_operation","multiple"),

    # Algorithm and transport settings in application and infrastructure config
    SignatureRule("CFG-ALGORITHM","config","Configuration","algorithm/cipher setting",r"(?:cipher|algorithm|digest|hash|signature|key[-_ ]?(?:exchange|algorithm))['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_./+-]+","Unknown","configuration","configuration", "configuration", "medium"),
    SignatureRule("CFG-TLS","config","TLS Configuration","TLS settings",r"\b(?:ssl_(?:ciphers|protocols|minimum_protocol_version)|tls[_-]?(?:version|cipher|ciphers|minimum_version)|minVersion|secureProtocol)\b","TLS","protocol_configuration","transport_security", "configuration", "medium"),
    SignatureRule("CFG-PQC","config","PQC Configuration","PQC algorithm setting",r"\b(?:ML[-_]?KEM|ML[-_]?DSA|SLH[-_]?DSA|Kyber|Dilithium|SPHINCS)\b","ML-KEM","configuration","multiple", "configuration", "medium"),
    SignatureRule("CFG-CRYPTO-DEPENDENCY","config","Dependency manifest","cryptographic library dependency",r"\b(?:cryptography|pycryptodome|pyca|openssl|ring|rustls|rsa|sha2|sha3|ed25519-dalek|x25519-dalek|crypto-js|jsonwebtoken|node-forge|bcrypt|libsodium|sodiumoxide|BouncyCastle|bcprov|System\.Security\.Cryptography)\b","Unknown","dependency","dependency_inventory", "dependency_reference", "medium"),
]

RULES_BY_LANGUAGE = {}
for rule in SIGNATURE_RULES:
    RULES_BY_LANGUAGE.setdefault(rule.language, []).append(rule)

if "typescript" not in RULES_BY_LANGUAGE:
    RULES_BY_LANGUAGE["typescript"] = RULES_BY_LANGUAGE.get("javascript", [])
