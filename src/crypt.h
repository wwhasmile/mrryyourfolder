#ifndef MYF_CRYPT_H
#define MYF_CRYPT_H

#include <myf.h>

bool Crypt_Encrypt(const char *password, const wchar_t **ignore);
bool Crypt_Decrypt(const char *password, const wchar_t **ignore);

#endif // MYF_CRYPT_H
