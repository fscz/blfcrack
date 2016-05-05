#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "bcrypt.h"

#define _PASSWORD_LEN     128             /* max length, not counting NUL */
#define MAX_USERNAME_LENGTH   60
#define C_SALT_SIZE       16
#define SALT_SIZE       C_SALT_SIZE * 4 / 3     /* base64encoded */
#define HASH_SIZE       (7 + (16 * 4 + 2) / 3 + 1)


static void abort_with_usage() {
  printf("usage: blfcrack -d dictionary_file -p password_file\n");
  exit(1);
}

static char** str_split(char* a_str, const char a_delim) {
  char** result    = 0;
  size_t count     = 0;
  char* tmp        = a_str;
  char* last_comma = 0;
  char delim[2];
  delim[0] = a_delim;
  delim[1] = 0;

  /* Count how many elements will be extracted. */
  while (*tmp)
  {
    if (a_delim == *tmp)
    {
      count++;
      last_comma = tmp;
    }
    tmp++;
  }

  /* Add space for trailing token. */
  count += last_comma < (a_str + strlen(a_str) - 1);

  /* Add space for terminating null string so caller
     knows where the list of returned strings ends. */
  count++;

  result = malloc(sizeof(char*) * count);

  if (result)
  {
    size_t idx  = 0;
    char* token = strtok(a_str, delim);

    while (token)
    {
      *(result + idx++) = strdup(token);
      token = strtok(0, delim);
    }
    *(result + idx) = 0;
  }

  return result;
}


int main(int argc, char* argv[]) {

  //char* foohash = "$2b$08$GrRLT9rm6XkPjccN4jEor.kdgsIPQ1jccP3aP/k1u/Z0N51CGy5Ai";
  char* fsczhash = "$2b$09$w1QtQlKNsIpcVfKXR6sxou1RAt8jDREorXEpbi1QePrCMgIR.wysK";

  char h[128];

  char* dictionary_file = NULL;
  char* password_file = NULL;
  int c;

  opterr = 0;
  while ((c = getopt (argc, argv, "d:p:r:")) != -1) {
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
  size_t line_len = 0;
  int read = 0;
  int i = 0;
  while ((read = getline(&line, &line_len, passwords)) != -1) {
    char** tokens = str_split(line, ':');
    strcpy(usernames[i], tokens[0]);
    strcpy(hashes[i], tokens[1]);
    free (tokens);
    i++;
  }
  fclose(passwords);

  while ((read = getline(&line, &line_len, dictionary)) != -1) {
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