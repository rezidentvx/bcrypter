#include <windows.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include "bcrypter.h"
#include <winternl.h>
#pragma comment (lib, "bcrypt.lib")
#pragma comment (lib, "ntdll.lib")

NTSTATUS BCrypter::OpenAlgorithmProvider(LPCWSTR pszAlgID, LPCWSTR pszImplementation, DWORD dwFlags) {
    status = BCryptOpenAlgorithmProvider(&this->hAlg, pszAlgID, pszImplementation, dwFlags);
    return max(status, BCrypter::SetStatus(status));
}
NTSTATUS BCrypter::GetProperty(LPCWSTR pszProperty, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags) {
    if (!cbOutput) { cbOutput = sizeof(pbOutput); }
    if (!pcbResult) {
        this->cb = 0;
        pcbResult = &this->cb;
    }
    status = BCryptGetProperty(this->hAlg, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
    return max(status, BCrypter::SetStatus(status));
}
NTSTATUS BCrypter::SetProperty(LPCWSTR pszProperty, PUCHAR pbInput, ULONG dwFlags) {
    status = BCryptSetProperty(this->hAlg, pszProperty, pbInput, sizeof(pbInput), dwFlags);
    return max(status, BCrypter::SetStatus(status));
}

//template<typename T>
//NTSTATUS BCrypter::GenerateSymmetricKey(std::vector<T> pbSecret, ULONG dwFlags) {
//    return BCrypter::GenerateSymmetricKey(pbSecret.data(), pbSecret.size() * sizeof(T), dwFlags);
//}
//template<typename T>
//NTSTATUS BCrypter::GenerateSymmetricKey(T pSecret, ULONG cbSecret, ULONG dwFlags) {
//    //NTSTATUS BCrypter::GenerateSymmetricKey(PVOID pSecret, ULONG cbSecret, ULONG dwFlags) {
//    auto pbSecret = pSecret;
//    // I know this is nasty. Working on it.
//    while(!cbSecret){
//        try {
//            cbSecret = *(&pSecret + 1) - pSecret;
//            if (!cbSecret) cbSecret = *(&pSecret + 1) - pSecret;
//            if (!cbSecret) cbSecret = pbSecret - FindNull(pbSecret);
//            if (!cbSecret) throw "Could not assess length of pSecret.";
//        }
//        catch (...)
//            return PrintError(); 
//    }
//    return BCrypter::GenerateSymmetricKey((PUCHAR)pSecret, cbSecret, dwFlags);
//}
NTSTATUS BCrypter::GenerateSymmetricKey(PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags){
    if (!cbSecret) cbSecret = GetPointerLength(pbSecret);
    status = BCryptGenerateSymmetricKey(this->hAlg, &this->hKey, (PUCHAR)&this->pbKeyObject, sizeof(this->pbKeyObject), (PUCHAR)pbSecret, cbSecret, dwFlags);
    return max(status, BCrypter::SetStatus(status));
}

NTSTATUS BCrypter::ExportKey(LPCWSTR pszBlobType, PUCHAR pbBlob, ULONG cbBlob, BCRYPT_KEY_HANDLE hExportKey, ULONG dwFlags) {
    status = BCryptExportKey(this->hKey, hExportKey, pszBlobType, pbBlob, sizeof(pbBlob), &cbBlob, dwFlags);
    return max(status, BCrypter::SetStatus(status));
}
NTSTATUS BCrypter::ImportKey(LPCWSTR pszBlobType, PUCHAR pbBlob, BCRYPT_KEY_HANDLE hImportKey, ULONG dwFlags) {
    status = BCryptImportKey(this->hAlg, hImportKey, pszBlobType, &this->hKey, (PUCHAR)&this->pbKeyObject, this->cb/*bugged*/, pbBlob, sizeof(pbBlob), dwFlags);
    return max(status, BCrypter::SetStatus(status));
}
NTSTATUS BCrypter::Encrypt(ULONG dwFlags) {
    status = BCryptEncrypt(this->hKey, (PUCHAR)&this->pbPlainText, sizeof(this->pbPlainText), pPaddingInfo, (PUCHAR)&this->pbIV, this->cb/*bugged*/, (PUCHAR)&this->pbCipherText, sizeof(this->pbCipherText), &this->cb/*bugged*/, dwFlags);
    return max(status, BCrypter::SetStatus(status));
}
NTSTATUS BCrypter::Decrypt(ULONG dwFlags) {
    status = BCryptDecrypt(this->hKey, (PUCHAR)&this->pbCipherText, this->cb/*bugged*/, pPaddingInfo, (PUCHAR)&this->pbIV, this->cb/*bugged*/, (PUCHAR)&this->pbPlainText, sizeof(this->pbPlainText), &this->cb/*bugged*/, dwFlags);
    return max(status, BCrypter::SetStatus(status));
}
NTSTATUS BCrypter::DestroyKey() {
    status = BCryptDestroyKey(&this->pbKeyObject);
    return max(status, BCrypter::SetStatus(status));
}

BOOL BCrypter::SetStatus(NTSTATUS status) {
    if (status) PrintError(status);
    return (this->status = status) != status;
}

template<typename T>
std::string PrintError(NTSTATUS code, T &output) {
    std::stringstream stream;
    //if (dynamic_cast<std::ostream *>(&output))
    //    dynamic_cast<T*>(&stream);

    // Example output:
    // GetLastError(): 0xC0000135
    // NTSTATUS Received: 0xC000000D : The parameter was invalid
    DWORD error = GetLastError();
    stream << "GetLastError(): " << error << "\n";

    // TODO: De-duplicate with the #pragma include at the top
        // What size does this add to the PE or process, respectively?
    HMODULE hNtDll = LoadLibrary(L"ntdll.dll");
    stream << "NTSTATUS Received: 0x" << std::hex << code;
    if (hNtDll != NULL && code) {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, RtlNtStatusToDosError(code), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        std::string message(messageBuffer, size);
        stream << " : " << message;
        FreeLibrary(hNtDll);
    }

    if (dynamic_cast<std::ostream*>(&output))
        output << stream.str() << std::endl;
    return stream.str();
}

template<typename T>
T* FindNull(T* pbz, SIZE_T maxLen, const BYTE flStop) {
    auto pb = (PBYTE)pbz;
    while (maxLen-- || flStop & STOP_MAX) {
        try {
            if (!pb++) {
                pbz = pb;
                if (flStop & STOP_NULL) break;
            }
        }
        catch (...) { break; }
    }
    return pbz;
}