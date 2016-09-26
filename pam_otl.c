#include <stdlib.h>
#include <pwd.h>
#include <syslog.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "otl.h"

static int request_pass(pam_handle_t *pamh)
{
	struct pam_message msg = {
		.msg_style = PAM_PROMPT_ECHO_OFF,
		.msg = "password: ",
	};
	struct pam_conv *conv;
	const struct pam_message *msgs[1] = {&msg};
	struct pam_response *resp = NULL;
	volatile char *c;
	int ret;

	ret = pam_get_item(pamh, PAM_CONV, (void*)&conv);
	if (ret != PAM_SUCCESS) {
		syslog(LOG_NOTICE, "pam_get_item(PAM_CONV) failed: %s",
		       pam_strerror(pamh, ret));
		return ret;
	}

	ret = conv->conv(1, msgs, &resp, conv->appdata_ptr);
	if (ret != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
	    *resp->resp == '\000') {
		if (ret != PAM_SUCCESS) {
			syslog(LOG_NOTICE, "conversation failed: %s",
			       pam_strerror(pamh, ret));
			return ret;
		} else {
			syslog(LOG_NOTICE, "conversion bad response");
			return PAM_AUTH_ERR;
		}
	}

	/* store response as PAM item */
	ret = pam_set_item(pamh, PAM_AUTHTOK, resp[0].resp);
	if (ret != PAM_SUCCESS) {
		syslog(LOG_NOTICE, "pam_set_item(password) failed: %s",
		       pam_strerror(pamh, ret));
		return ret;
	}

	/* sanitize buffer */
	for (c = resp[0].resp; *c; c++)
		*c = 0;

	free(resp[0].resp);
	free(resp);

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char **argv)
{
	int fd, ret;
	struct passwd *pw;
	const char *username;
	char filepath[PATH_MAX];
	char saved_pass[PASSWORD_SIZE + 1];
	char *given_pass;
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

	memset(saved_pass, 0, PASSWORD_SIZE + 1);

	ret = read(fd, saved_pass, PASSWORD_SIZE);
	if (ret != PASSWORD_SIZE) {
		if (ret == -1) {
			syslog(LOG_NOTICE, "read failed: %m");
		} else {
			syslog(LOG_NOTICE, "partial read: %d", ret);
		}
		return PAM_AUTH_ERR;
	}

	ret = request_pass(pamh);
	if (ret != PAM_SUCCESS)
		return ret;

	ret = pam_get_item(pamh, PAM_AUTHTOK, (const void**)&given_pass);
	if (ret != PAM_SUCCESS) {
		syslog(LOG_NOTICE, "pam_get_item(PAM_AUTHTOK) failed: %s",
		       pam_strerror(pamh, ret));
		return PAM_AUTH_ERR;
	}

	if (!given_pass) {
		syslog(LOG_NOTICE, "pam_get_item(PAM_AUTHTOK) returned NULL");
		return PAM_AUTH_ERR;
	}

	ret = strncmp(saved_pass, given_pass, strlen(saved_pass));
	if (ret) {
		syslog(LOG_AUTH, "user %s provided wrong password", username);
		return PAM_AUTH_ERR;
	}

	ret = close(fd);
	if (ret) {
		syslog(LOG_NOTICE, "close failed: %m");
		return PAM_AUTH_ERR;
	}

	syslog(LOG_AUTH, "user %s login successful", username);

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			      const char **argv)
{
  return PAM_SUCCESS;
}
