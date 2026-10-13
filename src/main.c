#include <stdio.h>
#include <password_generator.h>

int main(int argc, char **argv)
{
	char pwd[9] = { '\0' };
	PasswordGenerator_GenerateCode(pwd, sizeof(uint64_t));

	printf("%s!", pwd);
	return 0;
}
