#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <time.h>
#include <mpi.h>
#include <ctime>
//mpic++ -o MPI_output MPI_Solution.cpp -lcrypto


#define MAX_BUFFERSIZE 128

typedef unsigned char byte;

/* Function declarations */
int decryptor(byte *ciphertext_conteiner, int ciphertext_lenght, byte *key_container, byte *iv_container, byte *plaintext_container);
int encryptor(byte *plaintext_container, int plaintext_len, byte *key_container, byte *iv_container, byte *ciphertext_conteiner);

int main (int argc, char** argv)
{
  /* Execution time */
  int start_s=clock();

  /* A 128 bit key  <16 characters>*/
  byte *key_container = (byte *)"#####aa^~?@#####";

  /* ASCII character set  <simplified excluding space and detete symbols and two # symbols for padding to make ASCII char set devisible by 4>*/
  byte * asciiStuff = (byte *) "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!/\"#$&\'()*+,-./0123456789:;<=>?@[/]^_`{|}~##";

  /* A 128 bit IV <16 characters>*/
  byte *iv_container = (byte *)"5432109876543210";

  /* Message which will be encrypted */
  byte *plaintext_container = (byte *)"This is my own text for encryption";

  /* Buffer for ciphertext */
  byte ciphertext_conteiner[MAX_BUFFERSIZE];

  /* Buffer for the decrypted text */
  byte decryptedtext[MAX_BUFFERSIZE];

  /* Buffer for key cracker */
  byte combinationContainer[] = "################";

  int decryptedtext_len, ciphertext_len, combinations_attempted;

  bool agent = false;

  /* Crypto library inits calls */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  /* Enctyption of the plaintext */
  ciphertext_len = encryptor (plaintext_container, strlen ((char *)plaintext_container), key_container, iv_container, ciphertext_conteiner);


  // Initialize the MPI environment
  MPI_Init(NULL, NULL);

  // Get the number of processes
  int process_size;
  MPI_Comm_size(MPI_COMM_WORLD, &process_size);

  // Get the rank of the process
  int process_id;
  MPI_Comm_rank(MPI_COMM_WORLD, &process_id);

  // Get the name of the processor
  char processor_name[MPI_MAX_PROCESSOR_NAME];
  int name_len;
  MPI_Get_processor_name(processor_name, &name_len);

  std::cout<< "Program is running on: "<< processor_name << std::endl;

  /* Key Cracker starts*/
  for (process_id; process_id < 96; process_id += process_size )
  {
      combinationContainer[5] = asciiStuff[process_id];
      std::cout << "\033[1;35m Thread: ===>\033[0m" << process_id <<std::endl;

      for (int j = 0; j < 96; j++)
      {
          combinationContainer[6] = asciiStuff[j];

          for (int k = 0; k < 96; k++)
          {
              combinationContainer[7] = asciiStuff[k];

              for (int l = 0; l < 96; l++)
              {
                  combinationContainer[8] = asciiStuff[l];

                  for (int m = 0; m < 96; m++)
                  {
                      combinationContainer[9] = asciiStuff[m];

                      for (int n = 0 ; n < 96; n++)
                      {
                          combinationContainer[10] = asciiStuff[n];
          
                          decryptedtext_len = decryptor(ciphertext_conteiner, ciphertext_len, combinationContainer, iv_container, decryptedtext);
                          decryptedtext[decryptedtext_len] = '\0';

                          /* Call cleaning functions */
                          EVP_cleanup();
                          ERR_free_strings();

                              if (!strcmp((char *)plaintext_container, (char *)decryptedtext))
                              {
                                  std::cout << "\033[1;32m >>>>>EVP KEY CRACKED<<<<< \033[0m"<<std::endl;
                                  std::cout<<"\033[1;31m EVP KEY IS ===> \033[0m"<<combinationContainer<<std::endl;
                                  std::cout<<"\033[1;36m NUMBER OF COMBINATIONS ATTAMPTED ===> \033[0m"<< combinations_attempted<<std::endl;
                                  std::cout<<" "<<std::endl;
                                  agent = true;
                                  int stop_s=clock();
                                  std::cout << "\033[1;34m Solution execution time in miliseconds ===> \033[0m" << (stop_s-start_s)/double(CLOCKS_PER_SEC)*1000 << std::endl;
                                  MPI_Abort(MPI_COMM_WORLD, 0);
                                  MPI_Finalize();
                              }
                              else
                              {
                                combinations_attempted ++;
                              }
                      }
                  }
              }
          }
      }
  }
/* Key Cracker ends*/
MPI_Finalize();
  return 0;
 
}

/* Encryptor function body*/
int encryptor(byte *plaintext_container, int plaintext_len, byte *key_container, byte *iv_container, byte *ciphertext_conteiner)
{
  EVP_CIPHER_CTX *ctx;

  int ciphertext_len, len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()));

  /* Initialise the decryption operation */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key_container, iv_container));

  /* Provide the message to be encrypted, and obtain the encrypted output. */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext_conteiner, &len, plaintext_container, plaintext_len));
  ciphertext_len = len;

  /* Finish off the encryption */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext_conteiner + len, &len));
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

/* Decryptor function body*/
int decryptor(byte *ciphertext_conteiner, int ciphertext_len, byte *key_container, byte *iv_container, byte *plaintext_container)
{
  EVP_CIPHER_CTX *ctx;

  int plaintext_len, len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()));

  /* Initialise the decryption operation. 
   * Useing 'EVP_aes_128_cbc' instead of */

  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key_container, iv_container));

  /* Get the plaintext output */
  if(1 != EVP_DecryptUpdate(ctx, plaintext_container, &len, ciphertext_conteiner, ciphertext_len));
  plaintext_len = len;

  /* Finish up  decryption */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext_container + len, &len));
  plaintext_len += len;

  /* Clean up library functions calls with ctx cypher passed in */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}