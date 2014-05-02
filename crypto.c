#include        <string.h>
#include        <stdio.h>
#include        <stdlib.h>
#include        <openssl/evp.h>
#include        <openssl/aes.h>
#include        <sys/stat.h>


/////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//     ファイルの読み込み
//
//     fnameファイルから、データを読み込む。
//
unsigned char *read_file(int *len, char *fname)
{
  FILE   *fp;
  int i;
  struct stat sbuf;
  unsigned char *data,*k_data;

  if (len == NULL || fname == NULL) {
    return NULL;
  }

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



/////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//     文字列の暗号化(cbcモード)
//
unsigned char *str_enc(char *data, unsigned char *key, unsigned char *iv){
  EVP_CIPHER_CTX en;
  int datasize, i, c_len, f_len;
  unsigned char *ciphertext;

  f_len = 0;
  datasize = strlen(data);
  c_len = (datasize + EVP_MAX_BLOCK_LENGTH);
  ciphertext = calloc(c_len, sizeof(char));

  EVP_CIPHER_CTX_init(&en);
  EVP_EncryptInit_ex(&en, EVP_aes_128_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
  EVP_EncryptUpdate(&en, (unsigned char *)ciphertext, &c_len, (char *)data, datasize);
  EVP_EncryptFinal_ex(&en, (unsigned char *)(ciphertext + c_len), &f_len);

  printf("[C] = ");
  for(i=0; i < (c_len+f_len); i++){
    printf("%02x", ciphertext[i]);
  }
  putchar('\n');

  EVP_CIPHER_CTX_cleanup(&en);

  return ciphertext;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//     文字列の復号(cbcモード)
//
char *str_dec(unsigned char *enc_data, unsigned char *key, unsigned char *iv, int data_len) {
  EVP_CIPHER_CTX  de;
  int     p_len, f_len;
  char    *plaintext;

  f_len = 0;
  p_len = data_len;
  plaintext = calloc(p_len+1, sizeof(char));

  EVP_CIPHER_CTX_init(&de);
  EVP_DecryptInit_ex(&de, EVP_aes_128_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
  EVP_DecryptUpdate(&de, (unsigned char *)plaintext, &p_len, (unsigned char *)enc_data, data_len);
  EVP_DecryptFinal_ex(&de, (unsigned char *)(plaintext + p_len), &f_len);

  plaintext[p_len + f_len]='\0';
  printf("[%s]\n",plaintext);

  EVP_CIPHER_CTX_cleanup(&de);

  return plaintext;
}

int main(void)
{
  int len, len2, datasize;
  char data[201], *p;
  unsigned char *c, *key, *iv;

  key = read_file(&len, "k1.txt");
  iv  = read_file(&len2, "iv.txt");

  printf("enter the data[200 byte]:");
  scanf("%s", data);
  datasize = (strlen(data) / 16);

  c = str_enc(data, key, iv);
  p = str_dec(c, key, iv, 16*(datasize + 1));

  free(key);
  free(iv);
  free(c);
  free(p);

  return(0);
}
