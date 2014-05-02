#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/engine.h>

void print_hex(unsigned char *target_text, int text_len) {
  int i;

  printf("長さは%d:\n", text_len);
  printf("------------------- RSA -------------------------\n");
  for (i = 0; i < text_len; i++) {
    printf("%02x", target_text[i]);
    if(((i+1) % 20) == 0) {
      putchar('\n');
    }
  }
  putchar('\n');
  printf("-------------------------------------------------\n");
}

int main(int argc, char *argv[]) {
  RSA *rsa_pub_key, *rsa_pri_key;
  FILE *fp;
  int rsaInSize, rsaOutSize;
  unsigned char *enc_text, *dec_text;
  char planeData[] = "abcdefghijklmnopqrstuvwxyz";

  //  fp = fopen("publicKey.pem", "r");
  fp = fopen("publicKey.pem", "r");
  if( fp == NULL ) {
    printf("公開鍵オープンエラー\n");
    return 1;
  }

  if( (rsa_pub_key =  PEM_read_RSAPublicKey(fp, NULL, NULL, NULL)) == NULL ) {
    printf("公開鍵読み込みエラー\n");
    fclose(fp);
    return 1;
  }
  fclose(fp);

  rsaInSize = RSA_size(rsa_pub_key);
  enc_text = (char *)malloc(rsaInSize);
  memset(enc_text, '\0', rsaInSize);

  if( RSA_public_encrypt(strlen(planeData), planeData, enc_text, rsa_pub_key, RSA_PKCS1_OAEP_PADDING) < 0 ) {
    free(enc_text);
    RSA_free(rsa_pub_key);
    printf("RSA暗号エラー\n");
    return 1;
  }
  RSA_free(rsa_pub_key);

  printf("平文\n%s\n\n", planeData);
  print_hex(enc_text, rsaInSize);

  //ここから複合化
  fp = fopen("privateKey.pem", "r");
  if( fp == NULL ) {
    printf("秘密鍵オープンエラー\n");
    return 1;
  }

  if( (rsa_pri_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL ) {
    printf("秘密鍵読み込みエラー\n");
    fclose(fp);
    return 1;
  }
  fclose(fp);

  rsaOutSize = RSA_size(rsa_pri_key);
  dec_text = (char *)malloc(rsaOutSize);
  memset(dec_text, '\0', rsaOutSize);

  if( RSA_private_decrypt(rsaInSize, enc_text, dec_text, rsa_pri_key, RSA_PKCS1_OAEP_PADDING) < 0 ) {
    free(dec_text);
    RSA_free(rsa_pri_key);
    printf("RSA復号エラー\n");
    return 1;
  }
  RSA_free(rsa_pri_key);

  //復号した平文 
  printf("plain text = %s\n", dec_text);


  free(enc_text);
  free(dec_text);
  return 0;
}
