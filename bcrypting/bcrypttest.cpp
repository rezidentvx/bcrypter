#include <windows.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <iostream>
#include <stdio.h>
#include "bcrypter.h"
#pragma comment (lib, "bcrypt.lib")

#define CheckStatus(x) { if (x != STATUS_SUCCESS) { printf("\\x%x\n", x); return x; }}
//inline int CheckStatus(NTSTATUS status) {if (status != STATUS_SUCCESS) { return status;}}
NTSTATUS main() {
    const BYTE plaintext[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    static const BYTE iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    static const BYTE AESkey[] = {
        0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    }; 
    BCrypter b;
    //b.pbPlainText.assign(&plaintext[0], &plaintext[sizeof(plaintext)]);
    b.pbPlainText = std::vector<BYTE>(&plaintext[0], &plaintext[sizeof(plaintext)]);
    b.pbIV = std::vector<BYTE>(&iv[0], &iv[sizeof(iv)]);

    b.OpenAlgorithmProvider(BCRYPT_AES_ALGORITHM);
    
    // Calculate the size of the buffer to hold the KeyObject.
    DWORD objLen = 0;
    b.GetProperty(BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen);

    // Calculate the block length for the IV.
    DWORD blockLen = 0;
    b.GetProperty(BCRYPT_BLOCK_LENGTH, (PBYTE)&blockLen);

    // Ensure the blockLen is longer than the IV length.
    CheckStatus(b.cb > b.pbIV.size());

    // Set chaining mode
    b.SetProperty(BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC);

    // Generate the key from supplied input key bytes.
    b.GenerateSymmetricKey<>(AESkey);

    // Save another copy of the key for later.
    b.ExportKey(BCRYPT_OPAQUE_KEY_BLOB, NULL);
    // Allocate the buffer to hold the BLOB.
    PBYTE pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, b.cb);

    b.pbPlainText = std::vector<BYTE>(&plaintext[0], &plaintext[sizeof(plaintext)]);
    // Get the output buffer size.
    b.Encrypt();

    // Destroy the key and reimport from saved BLOB.
    b.DestroyKey(); // b.pbKeyObject.clear()?
    b.pbPlainText.clear();
    // We can reuse the key object.
    b.pbKeyObject.clear();
    
    // Reinitialize the IV because encryption would have modified it.
    b.pbIV = std::vector<BYTE>(&iv[0], &iv[sizeof(iv)]);

    //memcpy(b.pbIV, iv, b.cbBlockLen);
    b.ImportKey(BCRYPT_OPAQUE_KEY_BLOB, pbBlob);

    // Get the output buffer size.
    b.Decrypt();
    b.pbPlainText.reserve(b.cb); //TODO: Put in Decrypt
    b.pbPlainText.clear(); //TODO: Put in Decrypt
    b.Decrypt();
    CheckStatus(
        memcmp(b.pbPlainText.data(), (PBYTE)plaintext, sizeof(plaintext))
    );
    wprintf(L"Success!\n");
    system("pause");
    return b.status;
}

int main2() {
	const BYTE plaintext[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    static const BYTE iv[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    static const BYTE AESkey[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
NTSTATUS status = STATUS_SUCCESS;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD
        cbCipherText = 0,
        cbPlainText = 0,
        cbData = 0,
        cbKeyObject = 0,
        cbBlockLen = 0,
        cbBlob = 0;
    PBYTE
        pbCipherText = NULL,
        pbPlainText = NULL,
        pbKeyObject = NULL,
        pbIV = NULL,
        pbBlob = NULL;
    // Get algorithm handle to SHA256
    CheckStatus(
        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)
    );
    // Calculate the size of the buffer to hold the KeyObject.
    CheckStatus(
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0)
    );

    // Allocate the key object on the heap.
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);

    // Calculate the block length for the IV.
    CheckStatus(
        BCryptGetProperty(hAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&cbBlockLen, sizeof(DWORD), &cbData, 0)
    );

    // Determine whether the cbBlockLen is not longer than the IV length.
    CheckStatus(cbBlockLen > sizeof(iv));

    // Allocate a buffer for the IV. The buffer is consumed during the 
    // encrypt/decrypt process.
    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlockLen);
    memcpy(pbIV, iv, cbBlockLen);

    // Set chaining mode
    CheckStatus(
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)
    );
    // Generate the key from supplied input key bytes.
    CheckStatus(
        BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)AESkey, sizeof(AESkey), 0)
    );
    // Save another copy of the key for later.
    CheckStatus(
        BCryptExportKey(hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, 0, &cbBlob, 0)
    );
    // Allocate the buffer to hold the BLOB.
    pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
    CheckStatus(
        BCryptExportKey(hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, pbBlob, cbBlob, &cbBlob, 0)
    );
    cbPlainText = sizeof(plaintext);
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);

    memcpy(pbPlainText, plaintext, sizeof(plaintext));

    //
    // Get the output buffer size.
    //
    CheckStatus(
        BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL, pbIV, cbBlockLen, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING)
    );

    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);

    // Use the key to encrypt the plaintext buffer.
    // For block sized messages, block padding will add an extra block.
    CheckStatus(
        BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL, pbIV, cbBlockLen, pbCipherText, cbCipherText, &cbData, BCRYPT_BLOCK_PADDING)
    );
    // Destroy the key and reimport from saved BLOB.
    CheckStatus(
        BCryptDestroyKey(hKey)
    );
    pbPlainText = NULL;

    // We can reuse the key object.
    memset(pbKeyObject, 0, cbKeyObject);

    // Reinitialize the IV because encryption would have modified it.
    memcpy(pbIV, iv, cbBlockLen);

    CheckStatus(
        BCryptImportKey(hAlg, NULL, BCRYPT_OPAQUE_KEY_BLOB, &hKey, pbKeyObject, cbKeyObject, pbBlob, cbBlob, 0)
    );
    // Get the output buffer size.
    CheckStatus(
        BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, cbBlockLen, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING)
    );
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);

    CheckStatus(
        BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, cbBlockLen, pbPlainText, cbPlainText, &cbPlainText, BCRYPT_BLOCK_PADDING)
    );
    CheckStatus(
        memcmp(pbPlainText, (PBYTE)plaintext, sizeof(plaintext))
    );
    wprintf(L"Success!\n");
}