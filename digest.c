#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <sys/stat.h>


/////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//     ファイルの読み込み
//
//     fnameファイルからデータを読み込む
//
unsigned char *read_file(int *len, char *fname)
{
  FILE   *fp;
  struct stat sbuf;
  unsigned char *data;

  if (len == NULL || fname == NULL) {
    return NULL;
  }

  printf("open binary\n");
  if (stat(fname, &sbuf) == -1) {
    return NULL;
  }
  *len = (int) sbuf.st_size;
  data = (unsigned char *) malloc(*len);
  if (!data) {
    return NULL;
  }
  if ((fp = fopen(fname, "rb")) == NULL) {
    return NULL;
  }
  if (fread(data, *len, 1, fp) < 1) {
    fclose(fp);
    return NULL;
  }
  return data;
  fclose(fp);

}

////////////////////////////////////////////////////////////////////////////////////////////////
//
//     ハッシュ計算
//
//     平文bufをalgアルゴリズムでハッシュ化しその結果を返す
//
unsigned char *digest(char *alg, char *buf, unsigned int len, unsigned int *olen){
  const EVP_MD *m;
  EVP_MD_CTX ctx;
  unsigned char *ret;

  OpenSSL_add_all_digests();

  m = EVP_get_digestbyname(alg);
  ret = (unsigned char *)malloc(EVP_MAX_MD_SIZE);

  EVP_DigestInit(&ctx, m);
  EVP_DigestUpdate(&ctx, buf, len);
  EVP_DigestFinal(&ctx, ret, olen);
  return ret;
}

int main(void) {
  int i;
  unsigned int len, outlen;
  char data[201];
  unsigned char *dig;

  printf("enter plain data[200]:");
  scanf("%s", data);

  len = strlen(data);
  dig = digest("sha256", data, len, &outlen);
  for(i = 0;i < outlen; i++) {
    printf("%02x", dig[i]);
  }
  putchar('\n');

  return 0;
}
