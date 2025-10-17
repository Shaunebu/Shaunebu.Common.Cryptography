using Shaunebu.Common.Cryptography;
using Shaunebu.Common.Cryptography.Enums;
using System.Security.Cryptography;

Console.WriteLine("🔐 Cryptography Service Demo");
Console.WriteLine("============================\n");

try
{
    // Demo 1: Symmetric Encryption
    await DemoSymmetricEncryption();

    // Demo 2: Hashing
    DemoHashing();

    // Demo 3: Password Hashing
    DemoPasswordHashing();

    // Demo 4: RSA Encryption & Signing
    DemoRSA();

    // Demo 5: ECDSA Signing
    DemoECDSA();

    // Demo 6: File Encryption
    await DemoFileEncryption();

    // Demo 7: Password Generation
    DemoPasswordGeneration();

    Console.WriteLine("\n🎉 All demos completed successfully!");
}
catch (Exception ex)
{
    Console.WriteLine($"❌ Error: {ex.Message}");
}

Console.WriteLine("\nPress any key to exit...");
Console.ReadKey();

static async Task DemoSymmetricEncryption()
{
    Console.WriteLine("1. 🔄 Symmetric Encryption");
    Console.WriteLine("---------------------------");

    var originalText = "Hello, World! This is a secret message!";
    Console.WriteLine($"Original text: {originalText}");

    // Generate keys for different algorithms
    var aesKey = GenerateRandomBytes(32); // 256-bit key
    var aesIV = GenerateRandomBytes(16);  // 128-bit IV
    var tripleDesKey = GenerateRandomBytes(24); // 192-bit key
    var tripleDesIV = GenerateRandomBytes(8);   // 64-bit IV

    var aesKeyTuple = (Convert.ToBase64String(aesKey), Convert.ToBase64String(aesIV));
    var tripleDesKeyTuple = (Convert.ToBase64String(tripleDesKey), Convert.ToBase64String(tripleDesIV));

    // AES-CBC
    var aesEncrypted = CryptographyService.Cypher(
        CryptType.Encrypt,
        originalText,
        aesKeyTuple,
        EncryptionAlgorithm.AesCbc
    );
    var aesDecrypted = CryptographyService.Cypher(
        CryptType.Decrypt,
        aesEncrypted,
        aesKeyTuple,
        EncryptionAlgorithm.AesCbc
    );
    Console.WriteLine($"AES-CBC: {aesDecrypted == originalText}");

    // AES-GCM
    var aesGcmEncrypted = CryptographyService.Cypher(
        CryptType.Encrypt,
        originalText,
        (aesKeyTuple.Item1, ""), // IV optional for GCM
        EncryptionAlgorithm.AesGcm
    );
    var aesGcmDecrypted = CryptographyService.Cypher(
        CryptType.Decrypt,
        aesGcmEncrypted,
        (aesKeyTuple.Item1, ""),
        EncryptionAlgorithm.AesGcm
    );
    Console.WriteLine($"AES-GCM: {aesGcmDecrypted == originalText}");

    // Triple DES
    var tripleDesEncrypted = CryptographyService.Cypher(
        CryptType.Encrypt,
        originalText,
        tripleDesKeyTuple,
        EncryptionAlgorithm.TripleDes
    );
    var tripleDesDecrypted = CryptographyService.Cypher(
        CryptType.Decrypt,
        tripleDesEncrypted,
        tripleDesKeyTuple,
        EncryptionAlgorithm.TripleDes
    );
    Console.WriteLine($"Triple DES: {tripleDesDecrypted == originalText}");

    Console.WriteLine();
}

static void DemoHashing()
{
    Console.WriteLine("2. 🔍 Hashing");
    Console.WriteLine("-------------");

    var data = "Hello, Hash World!";
    Console.WriteLine($"Data: {data}");

    var sha256Hash = CryptographyService.Hash(HashAlgorithmType.Sha256, data);
    var sha512Hash = CryptographyService.Hash(HashAlgorithmType.Sha512, data);

    Console.WriteLine($"SHA256: {sha256Hash}");
    Console.WriteLine($"SHA512: {sha512Hash}");

    // Verify same input produces same hash
    var sha256Hash2 = CryptographyService.Hash(HashAlgorithmType.Sha256, data);
    Console.WriteLine($"SHA256 consistent: {sha256Hash == sha256Hash2}");

    Console.WriteLine();
}

static void DemoPasswordHashing()
{
    Console.WriteLine("3. 🔑 Password Hashing");
    Console.WriteLine("----------------------");

    var password = "MySuperSecretPassword123!";
    Console.WriteLine($"Password: {password}");

    // PBKDF2 with SHA256
    var pbkdf2Hash = CryptographyService.HashPassword(
        password,
        PasswordHashAlgorithm.Pbkdf2Sha256,
        iterations: 100_000
    );
    Console.WriteLine($"PBKDF2-SHA256: {pbkdf2Hash.Substring(0, 50)}...");

    // PBKDF2 with SHA512
    var pbkdf2Sha512Hash = CryptographyService.HashPassword(
        password,
        PasswordHashAlgorithm.Pbkdf2Sha512,
        iterations: 100_000
    );
    Console.WriteLine($"PBKDF2-SHA512: {pbkdf2Sha512Hash.Substring(0, 50)}...");

    // Argon2id (modern recommended)
    var argon2Hash = CryptographyService.HashPassword(
        password,
        PasswordHashAlgorithm.Argon2id,
        iterations: 4
    );
    Console.WriteLine($"Argon2id: {argon2Hash.Substring(0, 50)}...");

    // Verification
    var isValid = CryptographyService.VerifyPassword(password, argon2Hash);
    var isInvalid = CryptographyService.VerifyPassword("wrongpassword", argon2Hash);

    Console.WriteLine($"Correct password: {isValid}");
    Console.WriteLine($"Wrong password: {isInvalid}");

    Console.WriteLine();
}

static void DemoRSA()
{
    Console.WriteLine("4. 🗝️ RSA Encryption & Signing");
    Console.WriteLine("-------------------------------");

    var originalData = "Confidential data for RSA encryption";
    Console.WriteLine($"Original data: {originalData}");

    // Generate RSA key pair
    var (publicKey, privateKey) = CryptographyService.GenerateRsaKeyPair(2048);
    Console.WriteLine("RSA Key Pair generated");

    // Encryption/Decryption
    var encrypted = CryptographyService.EncryptRsa(originalData, publicKey);
    var decrypted = CryptographyService.DecryptRsa(encrypted, privateKey);
    Console.WriteLine($"RSA Encryption/Decryption: {decrypted == originalData}");

    // Digital Signatures
    var signature = CryptographyService.SignData(originalData, privateKey);
    var isValidSignature = CryptographyService.VerifySignature(originalData, signature, publicKey);
    var isInvalidSignature = CryptographyService.VerifySignature("tampered data", signature, publicKey);

    Console.WriteLine($"Valid signature: {isValidSignature}");
    Console.WriteLine($"Invalid signature detection: {!isInvalidSignature}");

    Console.WriteLine();
}

static void DemoECDSA()
{
    Console.WriteLine("5. ✍️ ECDSA Signing");
    Console.WriteLine("-------------------");

    var dataToSign = "Important document content";
    Console.WriteLine($"Data to sign: {dataToSign}");

    // Generate ECDSA key pair
    var (publicKey, privateKey) = CryptographyService.GenerateEcdsaKeyPair();
    Console.WriteLine("ECDSA Key Pair generated");

    // Sign and verify
    var signature = CryptographyService.SignEcdsa(dataToSign, privateKey);
    var isValid = CryptographyService.VerifyEcdsa(dataToSign, signature, publicKey);
    var isInvalid = CryptographyService.VerifyEcdsa("tampered data", signature, publicKey);

    Console.WriteLine($"Valid ECDSA signature: {isValid}");
    Console.WriteLine($"Invalid ECDSA signature detection: {!isInvalid}");

    Console.WriteLine();
}

static async Task DemoFileEncryption()
{
    Console.WriteLine("6. 📁 File Encryption");
    Console.WriteLine("---------------------");

    // Create a test file
    var testContent = "This is sensitive file content that needs encryption!\nLine 2\nLine 3";
    var inputFile = "test_input.txt";
    var encryptedFile = "test_encrypted.enc";
    var decryptedFile = "test_decrypted.txt";

    await File.WriteAllTextAsync(inputFile, testContent);
    Console.WriteLine($"Created test file: {inputFile}");

    // Generate encryption keys
    var key = GenerateRandomBytes(32);
    var iv = GenerateRandomBytes(16);

    // Encrypt file
    await CryptographyService.EncryptFileAsync(inputFile, encryptedFile, key, iv);
    Console.WriteLine($"File encrypted: {encryptedFile}");

    // Decrypt file
    await CryptographyService.DecryptFileAsync(encryptedFile, decryptedFile, key, iv);
    Console.WriteLine($"File decrypted: {decryptedFile}");

    // Verify content
    var decryptedContent = await File.ReadAllTextAsync(decryptedFile);
    Console.WriteLine($"File encryption/decryption successful: {decryptedContent == testContent}");

    // Cleanup
    File.Delete(inputFile);
    File.Delete(encryptedFile);
    File.Delete(decryptedFile);

    Console.WriteLine();
}

static void DemoPasswordGeneration()
{
    Console.WriteLine("7. 🎲 Password Generation");
    Console.WriteLine("-------------------------");

    var simplePassword = CryptographyService.GeneratePassword(12, useSpecials: false);
    var complexPassword = CryptographyService.GeneratePassword(16, useSpecials: true);
    var longPassword = CryptographyService.GeneratePassword(24, useSpecials: true);

    Console.WriteLine($"Simple (12 chars, no specials): {simplePassword}");
    Console.WriteLine($"Complex (16 chars, with specials): {complexPassword}");
    Console.WriteLine($"Long (24 chars, with specials): {longPassword}");

    Console.WriteLine();
}

static byte[] GenerateRandomBytes(int length)
{
    var bytes = new byte[length];
    RandomNumberGenerator.Fill(bytes);
    return bytes;
}