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
