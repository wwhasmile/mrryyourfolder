#include <stdio.h>
#include <password_generator.h>

int main(int argc, char **argv)
{
	char code[9] = { '\0' };
	PasswordGenerator_GenerateCode(code, sizeof(uint64_t));
	char password[33] = { '\0' };
	PasswordGenerator_GeneratePlainTextPassword(password, 32, code, sizeof(uint64_t));

	printf("Code: %s, password: %s!", code, password);
	return 0;
}
