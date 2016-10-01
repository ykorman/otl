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

static int store_password(char *password, unsigned int len)
{
	int fd, ret, err = 0;
	char filepath[PATH_MAX];

	ret = sprintf(filepath, "%s/%s", getenv("HOME"), PASSWORD_FILE);
	if (ret < 0) {
		otl_err("failed to construct filepath\n");
		return -EFAULT;
	}

	fd = open(filepath, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		otl_err("open(%s) failed: %m\n", filepath);
		return -errno;
	}

	ret = write(fd, password, len);
	if (ret != len) {
		if (ret == -1) {
			otl_err("write failed: %m\n");
			err = -errno;
		} else {
			otl_err("failed to write password\n");
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
	int err;

	memset(password, 0, PASSWORD_SIZE + 1);

	err = generate_password(password, PASSWORD_SIZE);
	if (err)
		return err;

	printf("\n%s\n", password);

	err = store_password(password, PASSWORD_SIZE);
	if (err)
		return err;

	sodium_memzero(password, PASSWORD_SIZE);

	return 0;
}
