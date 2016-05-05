#ifndef bcrypt_h
#define bcrypt_h

int
bcrypt_newhash(const char *pass, int log_rounds, char *hash, size_t hashlen);

int
bcrypt_checkpass(const char *pass, const char *goodhash);

#endif