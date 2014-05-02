#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

#define PROC_TYPE_UNDEF   (-1)
#define PROC_TYPE_DECRYPT (1)
#define PROC_TYPE_ENCRYPT   (2)

#define KEY_TYPE_UNDEF    (-1)
#define KEY_TYPE_PRIVATE  (1)
#define KEY_TYPE_PUBLIC   (2)

static void printError(char *msg, unsigned long err);

int
main(int argc, char *argv[])
{
  int procType = PROC_TYPE_UNDEF;
  int keyType = KEY_TYPE_UNDEF;
  int ret;
  FILE *keyFile;
  FILE *inFile;
  FILE *outFile;
  RSA *key;

  ERR_load_crypto_strings();

  struct option options[] = {
    {"dec", 0, &procType, PROC_TYPE_DECRYPT},
    {"enc", 0, &procType, PROC_TYPE_ENCRYPT},
    {"pri", 0, &keyType, KEY_TYPE_PRIVATE},
    {"pub", 0, &keyType, KEY_TYPE_PUBLIC},
    {NULL, 0, NULL, 0}};

  while((ret = getopt_long(argc, argv, "", options, NULL))
        != -1);

  if (procType == PROC_TYPE_UNDEF
      || keyType == KEY_TYPE_UNDEF
      || (argc - optind) < 3)
    {
      fprintf(stderr, "Usage : %s (--dec|--enc) (--pri|--pub) keyFile inFile outFile\n", argv[0]);
      exit(-1);
    }

  // キーファイル
  keyFile = fopen(argv[optind], "r");
  if (keyFile == NULL)
    {
      perror(argv[optind]);
      exit(-1);
    }

  // 入力データファイル
  inFile = fopen(argv[optind + 1], "r");
  if (inFile == NULL)
    {
      perror(argv[optind + 1]);
      exit(-1);
    }

  // 出力ファイル
  outFile = fopen(argv[optind + 2], "w");
  if (outFile == NULL)
    {
      perror(argv[optind + 2]);
      exit(-1);
    }

  if (keyType == KEY_TYPE_PUBLIC)
    {
      // 公開鍵の読み込み
      key = PEM_read_RSAPublicKey(keyFile, NULL, NULL, NULL);
    }
  else if (keyType == KEY_TYPE_PRIVATE)
    {
      // 秘密鍵の読み込み
      key = PEM_read_RSAPrivateKey(keyFile, NULL, NULL, NULL);
    }

  if (key == NULL)
    {
      fprintf(stderr, "failed to read keyfile\n");
      exit(-1);
    }
  else
    {
      RSA_print_fp(stdout, key, 0);
      if(0 && RSA_check_key(key) != 1)
        {
          printError("failed to RSA_check_key",
                     ERR_get_error());
          exit(-1);
        }
    }

  int inlen;
  int outlen;
  long rsaSize = RSA_size(key);
  unsigned char *inbuf = malloc(rsaSize);
  unsigned char *outbuf = malloc(rsaSize);
  int readSize;

  if (procType == PROC_TYPE_ENCRYPT)
    {
      readSize = rsaSize - 11;
    }
  else if (procType == PROC_TYPE_DECRYPT)
    {
      readSize = rsaSize;
    }

  fprintf(stdout, "RSA_size = %ld\n", rsaSize);

  memset(inbuf, 0, rsaSize);
  while((inlen = fread(inbuf, 1, readSize, inFile)) > 0)
    {
      fprintf(stdout, "inlen = %d\n", inlen);
      memset(outbuf, 0, rsaSize);
      if (procType == PROC_TYPE_ENCRYPT)
        {
          if (keyType == KEY_TYPE_PUBLIC)
            {
              // 公開鍵で暗号化
              if((outlen = RSA_public_encrypt(inlen, inbuf, outbuf,
                                              key, RSA_PKCS1_PADDING)) == -1)
                {
                  printError("failed to RSA_public_encrypt",
                             ERR_get_error());
                  exit(-1);
                }
            }
          else if (keyType == KEY_TYPE_PRIVATE)
            {
              // 秘密鍵で暗号化
              if((outlen = RSA_private_encrypt(inlen, inbuf, outbuf,
                                               key, RSA_PKCS1_PADDING)) == -1)
                {
                  printError("failed to RSA_private_encrypt",
                             ERR_get_error());
                  exit(-1);
                }
            }
        }
      else if (procType == PROC_TYPE_DECRYPT)
        {
          if (keyType == KEY_TYPE_PUBLIC)
            {
              // 公開鍵で復号
              if((outlen = RSA_public_decrypt(inlen, inbuf, outbuf,
                                              key, RSA_PKCS1_PADDING)) == -1)
                {
                  printError("failed to RSA_public_decrypt",
                             ERR_get_error());
                  exit(-1);
                }
            }
          else if (keyType == KEY_TYPE_PRIVATE)
            {
              // 秘密鍵で復号
              if((outlen = RSA_private_decrypt(inlen, inbuf, outbuf,
                                               key, RSA_PKCS1_PADDING)) == -1)
                {
                  printError("failed to RSA_private_decrypt",
                             ERR_get_error());
                  exit(-1);
                }
            }
        }

      fwrite(outbuf, 1, outlen, outFile);
      memset(inbuf, 0, rsaSize);
    }
  free(inbuf);
  free(outbuf);

  fclose(inFile);
  fclose(outFile);

  ERR_free_strings();

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
