#include "password_generator.h"

#include <Windows.h>
#include <stdlib.h>

#include <assert.h>

bool PasswordGenerator_GenerateCode(char *output, size_t bufferSize)
{
	assert(output != NULL && bufferSize > 0);

	NTSTATUS status = BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, (PUCHAR)output, bufferSize, 0);
	if (status != 0)
		return false;

	for (size_t i = 0; i < bufferSize; ++i) {
		uint8_t b = (uint8_t)output[i];
		output[i] = b % (('9' + 1) - '0') + '0';
	}

	return true;
}

void PasswordGenerator_GeneratePlainTextPassword(char *output, size_t outputSize, char *code, size_t codeSize)
{
	assert(output != NULL && outputSize > 0 && code != NULL && codeSize > 0);

	uint32_t seed = 5381;
	for (size_t i = 0; i < codeSize; ++i)
		seed = ((seed << 5) + seed) ^ code[i];

	srand(seed);
	for (size_t i = 0; i < outputSize; ++i) {
		uint32_t c = rand() % (('~' + 1) - '!') + '!';
		output[i] = (char)c;
	}
}
