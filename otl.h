#ifndef _OTL_H
#define _OTL_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <time.h>
#include <sodium.h>

#define STORE_FILE ".otl"
#define PASSWORD_SIZE 64
#define HASH_SIZE crypto_pwhash_scryptsalsa208sha256_STRBYTES
#define TIMEOUT_SEC (3*60)

struct password_store {
	char	hash[HASH_SIZE];
	time_t	timestamp;
};

#endif
