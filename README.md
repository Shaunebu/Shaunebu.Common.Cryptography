# Shaunebu.Common.Cryptography 🔐



![NuGet Version](https://img.shields.io/nuget/v/Shaunebu.Common.Cryptography?color=blue&label=NuGet)

![NET Support](https://img.shields.io/badge/.NET%20-%3E%3D8.0-blueviolet) ![NET Support](https://img.shields.io/badge/.NET%20CORE-%3E%3D3.1-blueviolet) ![NET Support](https://img.shields.io/badge/.NET%20MAUI-%3E%3D%208.0-blueviolet) [![Support](https://img.shields.io/badge/support-buy%20me%20a%20coffee-FFDD00)](https://buymeacoffee.com/jcz65te)

**Shaunebu.Common.Cryptography** provides a **unified cryptography API** for .NET applications, supporting modern and legacy algorithms:
*   AES (CBC, GCM)
    
*   TripleDES
    
*   RSA (encrypt/decrypt, sign/verify)
    
*   ECDSA
    
*   Password hashing (PBKDF2, Argon2id)
    
*   Hashing (SHA256, SHA512)
    
*   DPAPI (Windows ProtectedData)
    
*   Secure password generation
    
It wraps the complexity of `System.Security.Cryptography` and **Konscious.Security.Cryptography** into a single, consistent, easy-to-use service.

* * *

🚀 Installation
---------------

`PM> Install-Package Shaunebu.Common.Cryptography`

**NuGet link:** Shaunebu.Common.Cryptography

* * *

⚙️ Configuration
----------------

```csharp
CryptographyService.DefaultAlgorithm = EncryptionAlgorithm.AesCbc;
CryptographyService.DefaultIterations = 100_000;
CryptographyService.DefaultKeySize = 32;
```

*   `DefaultAlgorithm`: AES-CBC (default), AES-GCM, TripleDES
    
*   `DefaultIterations`: Used for PBKDF2 / Argon2id
    
*   `DefaultKeySize`: Key length in bytes (e.g., 32 = 256-bit)
    

* * *

🔑 Symmetric Encryption
-----------------------

### AES / TripleDES (Encrypt / Decrypt)

```csharp
var (key, iv) = ("base64Key", "base64IV");
string encrypted = CryptographyService.Cypher(CryptType.Encrypt, "Hello World", (key, iv), EncryptionAlgorithm.AesCbc);
string decrypted = CryptographyService.Cypher(CryptType.Decrypt, encrypted, (key, iv), EncryptionAlgorithm.AesCbc);
```

### AES-GCM (Authenticated Encryption)

```csharp
var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
string encrypted = CryptographyService.Cypher(CryptType.Encrypt, "TopSecret", (key, ""), EncryptionAlgorithm.AesGcm);
string decrypted = CryptographyService.Cypher(CryptType.Decrypt, encrypted, (key, ""), EncryptionAlgorithm.AesGcm);
```

* * *

📂 File Encryption
------------------

```csharp
await CryptographyService.EncryptFileAsync("plain.txt", "secret.bin", keyBytes, ivBytes);
await CryptographyService.DecryptFileAsync("secret.bin", "plain.txt", keyBytes, ivBytes);
```

Uses **AES-CBC** with PKCS7 padding.

* * *

🔐 Hashing
----------

```csharp
string hash1 = CryptographyService.Hash(HashAlgorithmType.Sha256, "data");
string hash2 = CryptographyService.Hash(HashAlgorithmType.Sha512, "data");
```

* * *

🔑 Password Hashing (PBKDF2 + Argon2id)
---------------------------------------

### Hash a password

```csharp
string stored = CryptographyService.HashPassword("MyPassword123!", PasswordHashAlgorithm.Argon2id);
```

Stored format:

```ruby
Algorithm:Iterations:Salt:Hash
```

### Verify a password

```csharp
bool valid = CryptographyService.VerifyPassword("MyPassword123!", stored);
```

Supports:
*   **PBKDF2-SHA256**
    
*   **PBKDF2-SHA512**
    
*   **Argon2id** (recommended)
    

* * *

🔏 RSA
------

### Generate Key Pair

```csharp
var (pub, priv) = CryptographyService.GenerateRsaKeyPair(2048);
```

### Encrypt / Decrypt

```csharp
string cipher = CryptographyService.EncryptRsa("SecretMessage", pub);
string plain = CryptographyService.DecryptRsa(cipher, priv);
```

### Sign / Verify

```csharp
string signature = CryptographyService.SignData("Message", priv);
bool valid = CryptographyService.VerifySignature("Message", signature, pub);
```

* * *

📝 ECDSA
--------

### Generate Key Pair

```csharp
var (pub, priv) = CryptographyService.GenerateEcdsaKeyPair();
```

### Sign / Verify

```csharp
string signature = CryptographyService.SignEcdsa("Message", priv);
bool ok = CryptographyService.VerifyEcdsa("Message", signature, pub);
```

* * *

🛡 Windows Data Protection (DPAPI)
----------------------------------

> Only available on **Windows**.

```csharp
string protectedText = CryptographyService.Protect("SensitiveValue");
string plain = CryptographyService.Unprotect(protectedText);
```

Uses `ProtectedData` with `CurrentUser` scope.

* * *

🔐 Password Generator
---------------------

```csharp
string pwd1 = CryptographyService.GeneratePassword(16);            // Letters, digits, specials
string pwd2 = CryptographyService.GeneratePassword(12, false);     // Letters + digits only
```

* * *

📊 Supported Algorithms
-----------------------

| Category | Supported | Notes |
| --- | --- | --- |
| AES | CBC, GCM | CBC for compatibility, GCM for authenticated encryption |
| TripleDES | CBC | Legacy support |
| RSA | Encrypt/Decrypt, Sign/Verify | OAEP-SHA256 & PKCS1 |
| ECDSA | P-256 | SHA256 signing |
| Hashing | SHA256, SHA512 |  |
| Password Hashing | PBKDF2-SHA256, PBKDF2-SHA512, Argon2id | Argon2id recommended |
| DPAPI | Windows only | Protect/Unprotect |
| Password Generator | Random, customizable | Secure RNG |

* * *

✅ Example Flow
--------------

```csharp
// Generate RSA key pair
var (pub, priv) = CryptographyService.GenerateRsaKeyPair();

// Encrypt and decrypt
var cipher = CryptographyService.EncryptRsa("Hello", pub);
var plain = CryptographyService.DecryptRsa(cipher, priv);

// Sign and verify
var sig = CryptographyService.SignData("Hello", priv);
var valid = CryptographyService.VerifySignature("Hello", sig, pub);

// Hash a password
var stored = CryptographyService.HashPassword("SuperSecret!");
var ok = CryptographyService.VerifyPassword("SuperSecret!", stored);
```

* * *

🔍 Why Use Shaunebu.Common.Cryptography?
----------------------------------------

*   ✅ **Unified API**: AES, RSA, ECDSA, Argon2id, PBKDF2 in one service
    
*   ✅ **Secure defaults**: Strong padding, key sizes, fixed-time compares
    
*   ✅ **Cross-platform**: Works on Windows, Linux, macOS (DPAPI only on Windows)
    
*   ✅ **Migration-friendly**: Supports multiple password algorithms
    
*   ✅ **Production ready**: Handles keys as Base64, easy to store