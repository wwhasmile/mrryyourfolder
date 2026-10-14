#include <stdio.h>
#include <password_generator.h>
#include <crypt.h>

int main(int argc, char **argv)
{
	char code[9] = { '\0' };
	PasswordGenerator_GenerateCode(code, sizeof(uint64_t));
	char password[33] = { '\0' };
	PasswordGenerator_GeneratePlainTextPassword(password, 32, code, sizeof(uint64_t));

	const wchar_t *ignore[] = { NULL };
	if (Crypt_Encrypt(password, ignore))
		Crypt_Decrypt(password, ignore);

	printf("Code: %s, password: %s!", code, password);
	return 0;
}
