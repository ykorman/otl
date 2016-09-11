#include <pwd.h>
#include <syslog.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "otl.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char **argv)
{
	int fd, ret;
	struct passwd *pw;
	const char *username;
	char filepath[PATH_MAX];
	char password[PASSWORD_SIZE + 1];
	char *service;
	char ident[64];

	ret = pam_get_item(pamh, PAM_SERVICE, (const void**) &service);
	if (ret != PAM_SUCCESS) {
		return PAM_AUTH_ERR;
	}

	ret = sprintf(ident, "%s(%s)", service, "pam_otl");
	if (ret < 0) {
		return PAM_AUTH_ERR;
	}

	openlog(ident, LOG_CONS | LOG_PID, LOG_AUTH);

	ret = pam_get_user(pamh, &username, NULL);
	if (ret != PAM_SUCCESS) {
		if (ret == PAM_CONV_AGAIN) {
			return PAM_INCOMPLETE;
		} else {
			syslog(LOG_NOTICE, "username not provided");
			return PAM_USER_UNKNOWN;
		}
	}

	pw = getpwnam(username);
	if (pw == NULL) {
		syslog(LOG_NOTICE, "error reading passwd entry");
		return PAM_USER_UNKNOWN;
	}

	ret = sprintf(filepath, "%s/%s", pw->pw_dir, PASSWORD_FILE);
	if (ret < 0) {
		syslog(LOG_NOTICE, "failed to construct filepath");
		return PAM_AUTH_ERR;
	}

	fd = open(filepath, O_RDONLY);
	if (fd == -1) {
		syslog(LOG_NOTICE, "open(%s) failed: %m\n",
			    filepath);
		return PAM_AUTHINFO_UNAVAIL;
	}

	memset(password, 0, PASSWORD_SIZE + 1);

	ret = read(fd, password, PASSWORD_SIZE);
	if (ret != PASSWORD_SIZE) {
		if (ret == -1) {
			syslog(LOG_NOTICE, "read failed: %m");
		} else {
			syslog(LOG_NOTICE, "partial read: %d", ret);
		}
		return PAM_AUTH_ERR;
	}

	/* TODO: get password from PAM and compare to file */

	ret = close(fd);
	if (ret) {
		syslog(LOG_NOTICE, "close failed: %m");
		return PAM_AUTH_ERR;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			      const char **argv)
{
  return PAM_SUCCESS;
}
