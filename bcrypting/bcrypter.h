#pragma once
#include <windows.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <vector>
#include <iostream>
#include <cassert>
#include <type_traits>
#pragma comment (lib, "bcrypt.lib")

// (GetLengthToNull) Stop and return upon
#define STOP_NULL 0x01 // (first NULL)
#define STOP_MAX  0x02 // maxLen
#define STOP_AV   0x04 // access violation
#define STOP_ANY  0xff // (any of the above)

template<typename T = std::ostream>
std::string PrintError(NTSTATUS code = NULL, T& output = std::cout);

template<typename T>
T* FindNull(T* pbz, SIZE_T maxLen = 0, const BYTE flStop = STOP_ANY);

template<typename T>
SIZE_T GetPointerLength(T* ptr) {
    SIZE_T len = 0;
    PBYTE pb = (PBYTE)ptr;
    // I know this is nasty. Working on it.
    try {
        //cbSecret? : 
        //    cbSecret = *(&pSecret + 1) - pSecret) ? : 
        //    cbSecret = pbSecret - FindNull(pbSecret) ? :
        //    assert(cbSecret)
        len = FindNull(pb) - pb;
        /*if (len = *(&pb + 1) - pb);
        else if (len = FindNull(pb) - pb);*/
        assert(len);
    }
    catch (...) { PrintError(); throw "Could not assess length of ptr contents."; }
    return len;
}

class BCrypter {
public:
    NTSTATUS status = STATUS_SUCCESS;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PVOID pPaddingInfo = NULL;
    //PBYTE
    //    pbCipherText = NULL,
    //    pbPlainText = NULL,
    //    pbKeyObject = NULL,
    //    pbIV = NULL;
    std::vector<BYTE>
        pbCipherText,
        pbPlainText,
        pbKeyObject,
        pbIV;
    DWORD
        cb = 0;

    NTSTATUS OpenAlgorithmProvider(LPCWSTR pszAlgID, LPCWSTR pszImplementation = NULL, DWORD dwFlags = 0);

    NTSTATUS GetProperty(LPCWSTR pszProperty, PUCHAR pbOutput, ULONG cbOutput = NULL, ULONG* pcbResult = NULL, ULONG dwFlags = 0);
    NTSTATUS SetProperty(LPCWSTR pszProperty, PUCHAR pbIntput, ULONG dwFlags = 0);

    //template<typename T>
    //NTSTATUS GenerateSymmetricKey(T arrSecret[], ULONG cbSecret = 0, ULONG dwFlags = 0) {
    //    if (!cbSecret) { cbSecret = sizeof(arrSecret); }
    //    return BCrypter::GenerateSymmetricKey(&arrSecret, cbSecret, dwFlags);
    //}
    template<typename T, const int N, std::enable_if_t<std::is_array<T[N]>::value, BOOL> = TRUE>
    //NTSTATUS GenerateSymmetricKey(T(&arrSecret)[], ULONG cbSecret = 0, ULONG dwFlags = 0) {
    NTSTATUS GenerateSymmetricKey(T (&arrSecret)[N], ULONG cbSecret = NULL, ULONG dwFlags = 0) {
        if (!cbSecret) { cbSecret = sizeof(arrSecret); }
        return BCrypter::GenerateSymmetricKey((PUCHAR)&arrSecret[0], cbSecret, dwFlags);
    }
    template<typename T>
    NTSTATUS GenerateSymmetricKey(std::vector<T> pSecret, ULONG cbSecret = NULL, ULONG dwFlags = 0) {
        if (!cbSecret) { cbSecret = pSecret.size() * sizeof(T); }
        return BCrypter::GenerateSymmetricKey(pSecret.data(), cbSecret, dwFlags);
    }
    template<typename T, std::enable_if_t<std::is_array<T>::value, BOOL> = FALSE>
    NTSTATUS GenerateSymmetricKey(T* pSecret, ULONG cbSecret = NULL, ULONG dwFlags = 0) {
        if (!cbSecret) { cbSecret = GetPointerLength(pSecret); }
        return BCrypter::GenerateSymmetricKey((PUCHAR)pSecret, cbSecret, dwFlags);
    }
    //template<typename T>
    //NTSTATUS GenerateSymmetricKey(T (&arrSecret)[], ULONG cbSecret = 0, ULONG dwFlags = 0) {
    //    if (!cbSecret) { cbSecret = sizeof(arrSecret); }
    //    return BCrypter::GenerateSymmetricKey(&arrSecret, cbSecret, dwFlags);
    //}
    //template<typename T>
    //NTSTATUS GenerateSymmetricKey(std::vector<T> pSecret, ULONG cbSecret = 0, ULONG dwFlags = 0) {
    //    if (!cbSecret) { cbSecret = pSecret.size() * sizeof(T); }
    //    return BCrypter::GenerateSymmetricKey(pSecret.data(), cbSecret, dwFlags);
    //}
    //template<typename T>
    ////NTSTATUS GenerateSymmetricKey(PVOID pSecret, ULONG cbSecret = NULL, ULONG dwFlags = 0) {
    //NTSTATUS GenerateSymmetricKey<T*>(T *pSecret, ULONG cbSecret = NULL, ULONG dwFlags = 0) {
    //    if (!cbSecret) { cbSecret = GetPointerLength(pSecret); }
    //    return BCrypter::GenerateSymmetricKey((PUCHAR)pSecret, cbSecret, dwFlags);
    //}
    NTSTATUS GenerateSymmetricKey(PUCHAR pbSecret, ULONG cbSecret = NULL, ULONG dwFlags = 0);

    NTSTATUS ExportKey(LPCWSTR pszBlobType, PUCHAR pbBlob, ULONG cbBlob = NULL, BCRYPT_KEY_HANDLE hExportKey = NULL, ULONG dwFlags = 0);
    NTSTATUS ImportKey(LPCWSTR pszBlobType, PUCHAR pbBlob, BCRYPT_KEY_HANDLE hImportKey = NULL, ULONG dwFlags = 0);

    NTSTATUS Encrypt(ULONG dwFlags = 0);
    NTSTATUS Decrypt(ULONG dwFlags = 0);

    NTSTATUS DestroyKey();

private:
    BOOL SetStatus(NTSTATUS status);
};