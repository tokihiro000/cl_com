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
//     fnameファイルから、len分のデータを読み込む
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



/////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//     文字列の暗号化(cbcモード)
//
//     lengthバイト文字列cの中身を１バイトずつ加算し、その値を返す
//
unsigned char *str_enc(char *data, unsigned char *key, unsigned char *iv){
  EVP_CIPHER_CTX en;
  int datasize, i, c_len, f_len=0, c[100];
  unsigned char *ciphertext, tmp[100];

  datasize = strlen(data);
  c_len = (datasize + EVP_MAX_BLOCK_LENGTH);
  ciphertext = calloc(c_len, sizeof(char));

  EVP_CIPHER_CTX_init(&en);
  EVP_EncryptInit_ex(&en, EVP_aes_128_cbc(), NULL, (unsigned char *)key, iv);
  EVP_EncryptUpdate(&en, (unsigned char *)ciphertext, &c_len, (unsigned char *)data, datasize);
  EVP_EncryptFinal_ex(&en, (unsigned char *)(ciphertext+c_len), &f_len);

  printf("[C] = ");
  for(i=0; i < (c_len+f_len); i++){
    printf("%02x", ciphertext[i]);
    c[i] = ciphertext[i];
  }
  putchar('\n');
  EVP_CIPHER_CTX_cleanup(&en);

  return ciphertext;
}


int main()
{
  int len, len2;
  char data[15];
  unsigned char *c, *key, *iv;

  key = read_file(&len, "k1.txt");
  iv  = read_file(&len2, "iv.txt");

  printf("enter the data[15 byte]:");
  scanf("%s", data);

  c = str_enc(data, key, iv);

  free(c);
  free(key);
  free(iv);
  return(0);
}
