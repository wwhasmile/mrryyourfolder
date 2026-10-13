#ifndef MYF_PASSWORD_GENERATOR_H
#define MYF_PASSWORD_GENERATOR_H

#include <myf.h>

bool PasswordGenerator_GenerateCode(char *output, size_t bufferSize);

void PasswordGenerator_GeneratePlainTextPassword(char *output, size_t outputSize, char *code, size_t codeSize);

#endif // MYF_PASSWORD_GENERATOR_H
