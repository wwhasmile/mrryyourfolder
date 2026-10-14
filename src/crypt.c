#include "crypt.h"

#include <string.h>
#define UNICODE
#include <Windows.h>

#define NT_SUCCESS(status) (status >= 0)

typedef BYTE CryptMagic[4];
typedef UCHAR CryptSalt[16];
typedef BYTE CryptIV[16];

static BOOL Crypt_IsEncrypted(HANDLE hFile, LONGLONG *pFileSize);
static BOOL Crypt_EncryptFile(LPWSTR pwszFilename, PUCHAR pbPassword, const wchar_t **ignore);

bool Crypt_Encrypt(const char *password, const wchar_t **ignore)
{
	Crypt_EncryptFile(L"hello.txt", (PUCHAR)password, ignore);
	return true;
}

BOOL Crypt_IsEncrypted(HANDLE hFile, LONGLONG *pFileSize)
{
	assert(hFile != NULL && hFile != INVALID_HANDLE_VALUE);

	LARGE_INTEGER liFileSize;
	if (!GetFileSizeEx(hFile, &liFileSize))
		return FALSE;
	if (pFileSize != NULL)
		*pFileSize = liFileSize.QuadPart;
	if (liFileSize.QuadPart <= sizeof(CryptMagic) + sizeof(ULONG) + sizeof(CryptIV) + sizeof(CryptSalt))
		return FALSE;

	CryptMagic magic = { 0 };
	if (!ReadFile(hFile, magic, sizeof(magic), NULL, NULL))
		return FALSE;
	LARGE_INTEGER liDistanceToMove = { 0 };
	SetFilePointerEx(hFile, liDistanceToMove, NULL, FILE_BEGIN);
	
	return magic[0] == '\t' && magic[1] == '\n' && magic[2] == 'M' && magic[3] == 'F';
}

BOOL Crypt_EncryptFile(LPWSTR filename, PUCHAR pbPassword, const wchar_t **ignore)
{
	assert(filename != NULL && pbPassword != NULL);

	/* Checking whether this file is in the ignore list. */
	if (ignore != NULL) {
		for (size_t i = 0; ignore[i] != NULL; ++i) {
			if (wcscmp(filename, ignore[i]) == 0)
				return FALSE;
		}
	}

	BOOL bResult = FALSE;

	HANDLE hFile = INVALID_HANDLE_VALUE;

	CryptIV IV = { 0 };
	CryptSalt salt;

	ULONG cbData;
	PUCHAR pbKeyObject = NULL;
	DWORD cbKeyObject;

	PUCHAR pbInput;
	LONGLONG cbInput;
	PUCHAR pbEncrypted;
	ULONG cbEncrypted;

	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;

	ULONG cbPassword = strlen((const char *)pbPassword);
	ULONG cbFilename = wcslen(filename);

	/* Opening file and extracting data */
	hFile = CreateFile(
		filename,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, 
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		goto cleanup;
	// If it's encrypted we REALLY don't want to encrypt it again.
	if (Crypt_IsEncrypted(hFile, &cbInput))
		goto cleanup;
	
	pbInput = HeapAlloc(GetProcessHeap(), 0, cbInput);
	if (pbInput == NULL)
		goto cleanup;
	if (!ReadFile(hFile, pbInput, cbInput, NULL, NULL))
		goto cleanup;
	CloseHandle(hFile);
	hFile = INVALID_HANDLE_VALUE;

	/* Setup - opening algorithm, generate IV, create a key */
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
			&hAlgorithm,
			BCRYPT_AES_ALGORITHM,
			NULL,
			0)))
		goto cleanup;
	if (!NT_SUCCESS(BCryptGetProperty(
			hAlgorithm,
			BCRYPT_OBJECT_LENGTH,
			(PUCHAR)&cbKeyObject,
			sizeof(DWORD),
			&cbData,
			0)))
		goto cleanup;
	
	// Generating an IV into the source buffer (later we'll copy it to avoid it getting modified). 
	if (!NT_SUCCESS(BCryptGenRandom(
			BCRYPT_RNG_ALG_HANDLE,
			(PUCHAR)&IV,
			sizeof(CryptIV),
			0)))
		goto cleanup;
	// Generating salt for key derivation. This one is in the function scope because we'll use it in the encrypted file.
	if (!NT_SUCCESS(BCryptGenRandom(
			BCRYPT_RNG_ALG_HANDLE,
			(PUCHAR)&salt,
			sizeof(CryptSalt),
			0)))
		goto cleanup;
	// Now we're generating the key.
	{
		// Data blob, because we're using a password and a salt.
		struct {
			BCRYPT_KEY_DATA_BLOB_HEADER header;
			UCHAR key[32];
		} blob;
		blob.header.dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
		blob.header.dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
		blob.header.cbKeyData = sizeof(blob.key);
		if (!NT_SUCCESS(BCryptDeriveKeyPBKDF2(
				BCRYPT_HMAC_SHA3_256_ALG_HANDLE,
				pbPassword,
				cbPassword,
				salt,
				sizeof(CryptSalt),
				10000,
				blob.key,
				sizeof(blob.key),
				0)))
			goto cleanup;
		
		pbKeyObject = HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
		if (pbKeyObject == NULL)
			goto cleanup;
		if (!NT_SUCCESS(BCryptImportKey(
				hAlgorithm,
				NULL,
				BCRYPT_KEY_DATA_BLOB,
				&hKey,
				pbKeyObject,
				cbKeyObject,
				(PUCHAR)&blob,
				sizeof(blob),
				0)))
			goto cleanup;
	}

	/* Now, we're actually encrypting the file. */
	// We're creating a copy of IV.
	CryptIV bufferIV;
	memcpy(bufferIV, IV, sizeof(CryptIV));

	// Getting output buffer size
	if (!NT_SUCCESS(BCryptEncrypt(
			hKey,
			pbInput,
			cbInput,
			NULL,
			bufferIV,
			sizeof(CryptIV),
			NULL,
			0,
			&cbEncrypted,
			BCRYPT_BLOCK_PADDING)))
		goto cleanup;
	pbEncrypted = HeapAlloc(GetProcessHeap(), 0, cbEncrypted);
	if (pbEncrypted == NULL)
		goto cleanup;
	if (!NT_SUCCESS(BCryptEncrypt(
			hKey,
			pbInput,
			cbInput,
			NULL,
			bufferIV,
			sizeof(CryptIV),
			pbEncrypted,
			cbEncrypted,
			&cbData,
			BCRYPT_BLOCK_PADDING)))
		goto cleanup;
	
	/* Creating the new file and writing the data there. */
	WCHAR wszOutputFilename[MAX_PATH] = { L'\0' };
	wcsncpy(wszOutputFilename, filename, cbFilename);
	wcsncpy(wszOutputFilename + cbFilename, L".myf", MAX_PATH - cbFilename);
	hFile = CreateFile(wszOutputFilename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		goto cleanup;
	
	// Writing magic
	CryptMagic magic = { '\t', '\n', 'M', 'F' };
	if (!WriteFile(hFile, magic, sizeof(magic), NULL, NULL))
		goto cleanup;
	if (!WriteFile(hFile, &cbEncrypted, sizeof(ULONG), NULL, NULL))
		goto cleanup;
	if (!WriteFile(hFile, pbEncrypted, cbEncrypted, NULL, NULL))
		goto cleanup;
	if (!WriteFile(hFile, salt, sizeof(CryptSalt), NULL, NULL))
		goto cleanup;
	if (!WriteFile(hFile, IV, sizeof(CryptIV), NULL, NULL))
		goto cleanup;

cleanup:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pbInput != NULL)
		HeapFree(GetProcessHeap(), 0, pbInput);
	if (pbEncrypted != NULL)
		HeapFree(GetProcessHeap(), 0, pbEncrypted);

	if (hAlgorithm != NULL)
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	if (hKey != NULL)
		BCryptDestroyKey(hKey);
	if (pbKeyObject != NULL)
		HeapFree(GetProcessHeap(), 0, pbKeyObject);

	return bResult;
}
