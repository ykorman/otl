# otl
One-time login for cloud instances.

Generate a temporary one-time login password.

## Why

Because cloud instances use SSH keys but web services hosted on these instances
require passwords.

## How to use

SSH to your cloud instance with your key and run otl:

```bash
$ ssh -i instance.key user@instance otl
VERYEXTREMELYREALLYLONGLONGLONGSECUREHASHEDGENERATEDPASSWORD
```
Now use this password to login to your web service:

