# otl
One-time login for cloud instances.

Generate a temporary one-time login password.

## Why

Because cloud instances use SSH keys but web sites require passwords.

## How to use

SSH to your cloud instance with your key and run otl:

```bash
$ ssh -i instance.key user@instance otl
VERYEXTREMELYREALLYLONGLONGLONGSECUREHASHEDGENERATEDPASSWORD
```
Use the returned password with the web site hosted on the instance:

<insert screenshot/video here>

This works for any website that uses locally defined users or any user
authentication method that passes through PAM.

The password is valid for one successful login and only for 3 minutes.

## Troubleshooting

### SELINUX

otl doesn't support SELINUX at the moment, so it should be disabled or switched
to permissive mode.

For example, if used with [Cockpit](http://cockpit-project.org), run the
following:
```bash
semanage permissive -a cockpit_session_t
```

## How to build & Install

### Dependencies

* libpam-devel
* libsodium-devel

For Debian/Ubuntu:
```bash
$ sudo apt-get install -y libpam0g-dev libsodium-dev
```

For Fedora/CentOS:
```bash
$ sudo yum install -y pam-devel libsodium-devel
```

### Build

```bash
$ make
```

### Install

Install manually by running:
```bash
$ sudo cp otl /usr/bin/
$ sudo cp pam_otl.so /usr/lib64/security/
```

(```make install``` soon to come...)

## Configure

otl authentication is implemented as a PAM (Pluggable Authentication Modules
for Linux) module.

To install it, add:
```
auth        sufficient    pam_otl.so
```
to /etc/pam.d/password-auth after the "auth sufficient pam_unix.so" line.


## License

MIT, See LICENSE

## TODO

See TODO

