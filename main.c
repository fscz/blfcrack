#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "bcrypt.h"

#define MAX_PASSWORD_SIZE     60
#define _PASSWORD_LEN         128             /* max length, not counting NUL */
#define MAX_USERNAME_LENGTH   60
#define C_SALT_SIZE           16
#define SALT_SIZE             C_SALT_SIZE * 4 / 3     /* base64encoded */
#define HASH_SIZE             (7 + (16 * 4 + 2) / 3 + 1)


static void abort_with_usage() {
  printf("usage: blfcrack -d dictionary_file -p password_file\n");
  exit(1);
}

int main(int argc, char* argv[]) {

  //char* foohash = "$2b$08$GrRLT9rm6XkPjccN4jEor.kdgsIPQ1jccP3aP/k1u/Z0N51CGy5Ai";
  //char* fsczhash = "$2b$09$w1QtQlKNsIpcVfKXR6sxou1RAt8jDREorXEpbi1QePrCMgIR.wysK";  

  char h[128];

  char* dictionary_file = NULL;
  char* password_file = NULL;
  int c;

  opterr = 0;
  while ((c = getopt (argc, argv, "d:p:")) != -1) {
    switch (c) {
    case 'd':
      dictionary_file = optarg;
      break;
    case 'p':
      password_file = optarg;
      break;
    default:
      abort_with_usage();
      break;
    }
  }

  if ( NULL == dictionary_file || NULL == password_file ) {
    abort_with_usage();
  }

  FILE* dictionary = fopen(dictionary_file, "r");
  if ( NULL == dictionary ) {
    perror(dictionary_file);
    return 1;
  }
  FILE* passwords = fopen(password_file, "r");
  if ( NULL == passwords ) {
    perror(password_file);
    return 1;
  }

  int ch;
  int password_count = 0;
  do
  {
    ch = fgetc(passwords);
    if (ch == '\n')
      password_count++;
  } while (ch != EOF);

  // skip the nobody line
  {
    password_count--;
    rewind(passwords);
    do
    {
      ch = fgetc(passwords);
      if (ch == '\n')
        break;
    } while (ch != EOF);
  }

  char usernames[password_count][MAX_USERNAME_LENGTH];
  char hashes[password_count][_PASSWORD_LEN];

  char* line = NULL;
  size_t lptr = 0;
  int read = 0;
  int i = 0;

  char* token;
  while ((read = getline(&line, &lptr, passwords)) != -1) {    
    token = strtok(line, ":");
    strcpy(usernames[i], token);

    token = strtok(NULL, ":");
    strcpy(hashes[i], token);

    i++;
  }
  fclose(passwords);

    
  while ((read = getline(&line, &lptr, dictionary)) != -1) {    

    line[read-1] = '\0';

    for (i = 0; i < password_count; i++) {    

      if ( 0 == bcrypt_checkpass(line, hashes[i]) ) {
        printf("%s: %s=>%s\n", usernames[i], line, hashes[i]);
        continue;
      }
      i++;
    }
  }

  if ( line != NULL) {
    free(line);
  }
  fclose(passwords);
}