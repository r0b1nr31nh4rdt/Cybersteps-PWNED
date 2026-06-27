# LFI & RFI
LFI was successfull, RFI was not.


## LFI - Directory Traversal
The following files I tested successfully

### seuccessfull paths
- /etc/passwd
- /etc/hosts
- /etc/apache2/apache2.conf

### unseuccessfull paths
- /etc/shadow
- /proc/self/environ
- /var/log/apache2/access.log



## RFI
With RFI I was not successfull. I think because the settings in the php.ini was set correctly.

```
allow_url_include = Off
allow_url_fopen = Off
```

I tried:
- remote shell
- phpinfo
- phpinfo in base64