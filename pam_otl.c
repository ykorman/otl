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

static int open_log(pam_handle_t *pamh)
{
	char *service;
	char ident[64];
	int ret;

	ret = pam_get_item(pamh, PAM_SERVICE, (const void**) &service);
	if (ret != PAM_SUCCESS) {
		return PAM_AUTH_ERR;
	}

	ret = sprintf(ident, "%s(%s)", service, "pam_otl");
	if (ret < 0) {
		return PAM_AUTH_ERR;
	}

	openlog(ident, LOG_CONS | LOG_PID, LOG_AUTH);

	return PAM_SUCCESS;
}

static int store_filepath(pam_handle_t *pamh, char *filepath)
{
	const char *username;
	struct passwd *pw;
	int ret;

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

	ret = sprintf(filepath, "%s/%s", pw->pw_dir, STORE_FILE);
	if (ret < 0) {
		syslog(LOG_NOTICE, "failed to construct filepath");
		return PAM_AUTH_ERR;
	}

	return PAM_SUCCESS;
}

static int load_store(const char *filepath, struct password_store *store)
{
	int fd, ret, err = PAM_SUCCESS;

	fd = open(filepath, O_RDONLY);
	if (fd == -1) {
		syslog(LOG_NOTICE, "open(%s) failed: %m\n",
			    filepath);
		return PAM_AUTHINFO_UNAVAIL;
	}

	ret = read(fd, store, sizeof(*store));
	if (ret != sizeof(*store)) {
		if (ret == -1) {
			syslog(LOG_NOTICE, "read failed: %m");
		} else {
			syslog(LOG_NOTICE, "partial read: %d", ret);
		}
		err = PAM_AUTH_ERR;
	}

	ret = close(fd);
	if (ret)
		syslog(LOG_NOTICE, "close failed: %m");

	return err;
}

static int check_timestamp(struct password_store *store)
{
	time_t now = time(NULL);
	double diff;

	diff = difftime(now, store->timestamp);
	if (diff > TIMEOUT_SEC) {
		syslog(LOG_AUTH, "password timeout\n");
		return PAM_AUTH_ERR;
	}

	return PAM_SUCCESS;
}

static int check_password(const struct password_store *store,
			  const char *pass)
{
	int ret;

	ret = crypto_pwhash_scryptsalsa208sha256_str_verify(store->hash, pass,
							    strlen(pass));
	if (ret) {
		syslog(LOG_AUTH, "wrong password");
		return PAM_AUTH_ERR;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char **argv)
{
	int ret;
	char filepath[PATH_MAX];
	char *given_pass;
	struct password_store store = {0};

	ret = open_log(pamh);
	if (ret)
		return ret;

	ret = store_filepath(pamh, filepath);
	if (ret != PAM_SUCCESS)
		return ret;

	ret = load_store(filepath, &store);
	if (ret != PAM_SUCCESS)
		return ret;

	ret = check_timestamp(&store);
	if (ret != PAM_SUCCESS)
		return ret;

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

	ret = check_password(&store, given_pass);
	if (ret != PAM_SUCCESS) {
		return ret;
	}

	syslog(LOG_AUTH, "login successful");

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			      const char **argv)
{
  return PAM_SUCCESS;
}
