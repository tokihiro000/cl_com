#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

static void printError(char *msg, unsigned long err);

int
main(int argc, char *argv[])
{
  int size = 1024;
  unsigned long expornent = 65537;
  FILE *privateKeyFile;
  FILE *publicKeyFile;

  if(argc != 3)
    {
      fprintf(stderr,
              "Usage : %s privateKeyFile publicKeyFile\n", argv[0]);
      exit(-1);
    }
  else
    {
      privateKeyFile = fopen(argv[1], "w");
      if (privateKeyFile == NULL)
        {
          perror("failed to fopen");
          exit(-1);
        }

      publicKeyFile = fopen(argv[2], "w");
      if (publicKeyFile == NULL)
        {
          perror("failed to fopen");
          exit(-1);
        }
    }

  // キーペアの作成
  RSA *rsaKey = RSA_generate_key(size, expornent, NULL, NULL);
  if (rsaKey == NULL)
    {
      printError("failed to RSA_generate_key",
                 ERR_get_error());
      exit(-1);
    }

  if(RSA_print_fp(stdout, rsaKey, 0) != 1)
    {
      printError("failed to RSA_print_fp",
                 ERR_get_error());
      exit(-1);
    }

  // 公開鍵をPEM形式で書き出し
  if(PEM_write_RSAPublicKey(publicKeyFile, rsaKey) != 1)
    {
      printError("failed to PEM_write_RSAPublicKey",
                 ERR_get_error());
      exit(-1);
    }

  // 秘密鍵をPEM形式で書き出し
  if(PEM_write_RSAPrivateKey(privateKeyFile, rsaKey,
                             NULL,
                             NULL, 0,
                             NULL, NULL) != 1)
    {
      printError("failed to PEM_write_RSAPrivateKey",
                 ERR_get_error());
      exit(-1);
    }

  // 領域の開放
  RSA_free(rsaKey);

  fclose(privateKeyFile);
  fclose(publicKeyFile);

  return 0;
}

static void
printError(char *msg, unsigned long err)
{
  char *errmsg = ERR_error_string(err, NULL);
  fprintf(stderr, "%s(%s)\n",
          msg,
          errmsg);
}
