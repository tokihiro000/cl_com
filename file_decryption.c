#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <sys/stat.h>


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
    printf("no name¥n");
    return NULL;
  }
  *len = (int) sbuf.st_size;
  data = (unsigned char *) malloc(*len);
  if (!data) {
    free(data);
    return NULL;
  }
  if ((fp = fopen(fname, "rb")) == NULL) {
    free(data);
    return NULL;
  }
  if (fread(data, *len, 1, fp) < 1) {
    fclose(fp);
    free(data);
    return NULL;
  }
  return data;
  free(data);
  fclose(fp);
 
}

int write_file(char *fname, unsigned char *data,int len)
{
  FILE   *fp;
 
  if (data == NULL || fname == NULL) {
    return 1;
  }
 
  printf("write binary\n");
  if ((fp = fopen(fname, "wb")) == NULL) {
    return 1;
  }
  if (fwrite(data, len, 1, fp) < 1) {
    fclose(fp);
    return 1;
  }
  fclose(fp);
  return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
//
//     ファイルの復号(cbcモード)
//
//     鍵key, ivをもとにファイル名inFileのファイルを読み込んで復号し、
//　　　outFileの名前で再びファイルとして書き込む
//
void file_decryption(unsigned char *key, unsigned char *iv, char *inFile, char *outFile){
  EVP_CIPHER_CTX  en;
  unsigned int ivLen = 16;
  int     inLen, outLen, out1, out2;
  unsigned char *intext, *outtext;
  const EVP_CIPHER *cipher;
 
  printf("File Decryption\n");
  cipher = EVP_aes_128_cbc();
 
  intext = read_file(&inLen, inFile);
  outtext = malloc(inLen + ivLen);

  EVP_CIPHER_CTX_init(&en);
  EVP_DecryptInit_ex(&en,cipher, NULL, (unsigned char *)key, (unsigned char *)iv);
  EVP_CIPHER_CTX_set_padding(&en, 1);
  EVP_DecryptUpdate(&en, outtext, &out1, intext, inLen);
  EVP_DecryptFinal_ex(&en, outtext + out1, &out2);

  outLen = out1 + out2;
 
  EVP_CIPHER_CTX_cleanup(&en);

  printf("write file\n");
  if( write_file(outFile, outtext, outLen) != 0){
    fprintf(stderr, "write file error!\n");
  }
 
  free(intext);
  free(outtext);
 
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
 
}

int main(void){
  char inname[30], outname[30];
  int len, len2;
  unsigned char *key, *iv;
  
  key = read_file(&len, "k1.txt");
  iv = read_file(&len2, "iv.txt");

  if(key == NULL || iv == NULL) {
    printf("key or iv is NULL");
    exit(EXIT_FAILURE);
  }

  printf("復号したいファイル名:");
  scanf("%s", inname);
  printf("復号後のファイル名:");
  scanf("%s", outname);
  
  file_decryption(key, iv, inname, outname);
  
  return 0;
}
