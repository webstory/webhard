# Webhard

Simple webhard in a single file.

**WARNING!** This program provides lacks of security.

## Known issues
 * Upload other PHP file and execute it.

Use this for small, personal purpose only.

Most important thing: Discard after use.

## INSTALL
Copy index.php file into your web directory.

## Setting(NginX and PHP)

### NginX configuration
In file /etc/nginx/nginx.conf

```
http {
  ##
  # Basic Settings
  ##

  client_max_body_size 2048m;
}
```

### php5.ini
In Ubuntu, php5.ini file located at /etc/php5/fpm/php5.ini
```
max_execution_time = 120
post_max_size = 2048M
file_upload = On
upload_max_filesize = 2048M
default_socket_timeout = 60

```

## Change password
 * Upload password.txt file which contains a new password.
 * Reload or logout
 * password.txt will be changed into password.hash and contains a new password.

## Useful Scenario
 * Upload index.php into web directory.
 * Upload password.txt file if you want to change password.
 * Upload other files.
 * Copy file URL and share your friend.
 * Remove index.php (Freeze directory)

## LICENSE
[MIT](LICENSE)
