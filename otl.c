#include <sodium.h>

#include "otl.h"

#define otl_dbg printf

#define otl_log printf

#define otl_err printf

#define BUF_SIZE 512

static int generate_password(char *password, unsigned int len)
{
	unsigned char buf[BUF_SIZE];
	int i, left = len;
	char *pi = password;

	memset(buf, 0, sizeof(buf));

	while (left) {
		randombytes_buf(buf, BUF_SIZE);

		for (i = 0; i < BUF_SIZE; ++i) {
			if (left && isalnum(buf[i])) {
				*pi = buf[i];
				++pi;
				--left;
			}
		}
	}

	sodium_memzero(buf, BUF_SIZE);

	return 0;
}

static int fill_store(struct password_store *store, char *password,
		      unsigned int len)
{
	int err;

	err = crypto_pwhash_scryptsalsa208sha256_str(store->hash, password, len,
						     crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
						     crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
	if (err) {
		otl_err("crypto_pwhash_scryptsalsa208sha256_str mem error\n");
		return -ENOMEM;
	}

	store->timestamp = time(NULL);

	return 0;
}

static int write_store(char *password, unsigned int len)
{
	int fd, ret, err = 0;
	char filepath[PATH_MAX];
	struct password_store store = {0};

	ret = fill_store(&store, password, len);
	if (ret)
		return ret;

	ret = sprintf(filepath, "%s/%s", getenv("HOME"), STORE_FILE);
	if (ret < 0) {
		otl_err("failed to construct filepath\n");
		return -EFAULT;
	}

	fd = open(filepath, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		otl_err("open(%s) failed: %m\n", filepath);
		return -errno;
	}

	ret = write(fd, &store, sizeof(store));
	if (ret != sizeof(store)) {
		if (ret == -1) {
			otl_err("write failed: %m\n");
			err = -errno;
		} else {
			otl_err("failed to write store\n");
			err = -ENOSPC;
		}
	}

	ret = close(fd);
	if (ret) {
		otl_err("close failed: %m\n");
		err = err ?: errno;
	}

	return err;
}

int main(int argc, char **argv)
{
	char password[PASSWORD_SIZE + 1];
	int err = 0;

	err = sodium_init();
	if (err == -1) {
		otl_err("sodium_init failed\n");
		return -EPERM;
	}

	sodium_memzero(password, PASSWORD_SIZE + 1);
	sodium_mlock(password, PASSWORD_SIZE + 1);

	err = generate_password(password, PASSWORD_SIZE);
	if (err)
		goto out;

	err = write_store(password, PASSWORD_SIZE);
	if (err)
		goto out;

	printf("%s", password);

out:
	sodium_munlock(password, PASSWORD_SIZE + 1);

	return 0;
}
