# rspamd-arc
Proof of concept uWSGI service that syncs OpenLDAP DKIM-Keys with Rspamd for DKIM/ARC signing

Introduction
============

I use OpenDKIM for DKIM signing and Rspamd as a anti spam solution. RSA keys are stored in a central OpenLDAP server. Rspamd itself support DKIM and ARC signing as well as verification.

My Rspamd configuration has DKIM signing disabled, but I like to use ARC signing. For this, Rspamd can use maps to determine the ARC selector and can use Redis for the RSA key store.

This uWSGI service runs behind Nginx and serves a ARC selector map derrived from OpenLDAP. It also automatically synchronizes the RSA keys with Redis.

My setup is a little bit special, as I use SASL/EXTERNAL with x509 certificates to communicate with the OpenLDAP service. This makes the current code a proof-of-concept, because I did not implement all LDAP features. Just the ones I need. But feel free to help and tweak the code ;-)

Note
----

This service can be used for DKIM and ARC support in Rspamd! This example only demonstrates the use for ARC

Requirements
============

- OpenLDAP server with TLS and SASL/EXTERNAL
- OpenDKIM LDAP schema
- Rspamd >=1.6.5
- Python modules memcache, redis and pyldap (needed for Python 3.x)
- uWSGI with Python support (tested with Python version 3.4)
- Nginx webserver

Setup
=====

Place the arc.py script under a path i.e. /usr/local/share/rspamd. Create a system user and group "arc" and change the owner of this script. Also set permissions to 640. Next step is to create a folder /var/log/arc, which also needs permissions for the "arc" user.

uWSGI (Gentoo example - /etc/conf.d/uwsgi.arc)
----------------------

```
UWSGI_SOCKET=127.0.0.1:9200
UWSGI_THREADS=1
UWSGI_PROGRAM=
UWSGI_XML_CONFIG=
UWSGI_PROCESSES=4
UWSGI_LOG_FILE="/var/log/arc/uwsgi.log"
UWSGI_CHROOT=
UWSGI_DIR=
UWSGI_PIDPATH_MODE=0750
UWSGI_USER=arc
UWSGI_GROUP=arc
UWSGI_EMPEROR_PATH=
UWSGI_EMPEROR_PIDPATH_MODE=0770
UWSGI_EMPEROR_GROUP=
UWSGI_EXTRA_OPTIONS="--plugin python34 --python-path /usr/local/share/rspamd --module arc"
```

Nginx
-----

Example for ARC usage. Add a location string for DKIM, if you want to use it for this task.

```
server {
        listen 127.0.0.1;
        server_name localhost;

        access_log /var/log/nginx/rspamd.access_log main;
        error_log /var/log/nginx/rspamd.error_log info;

        location ~ /arc {
                include uwsgi_params;
                uwsgi_pass 127.0.0.1:9200;
                error_log off;
         }
}
```

arc.py
------

If you open the script, you will find a section called configuration. Adopt the settigs to your needs. Here is the example from script:

LDAP settings:
```
LDAP_URL = "ldap://db.roessner-net.de/" \
           "ou=dkim,ou=it,dc=roessner-net,dc=de??" \
           "sub"
LDAP_TLS_CERT = "/etc/ssl/certs/mx.roessner-net.de.pem"
LDAP_TLS_KEY = "/etc/ssl/private/mx.roessner-net.de.key.pem"
```

memcache settings:
```
MC_URL = "127.0.0.1:11211"
MC_TTL = 3600
```

redis settings:
```
REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_HMNAME = "DKIM_ARC_KEYS"

DEBUG = True
```

Finally I added a "curl" call to the Rspamd init script, to clear the memcache key. Else Rspamd will not load a map from HTTP, if the service was restarted

```
curl -X DELETE --silent http://127.0.0.1/arc
```

Rspamd-settings
===============

Example file /etc/rspamd/local.d/arc.conf

```
# Settings copied from dkim_sign
allow_envfrom_empty = true;
allow_hdrfrom_mismatch = true;
allow_hdrfrom_multiple = false;
allow_username_mismatch = true;
auth_only = true;
selector_map = "http://127.0.0.1/arc";
sign_local = true;
symbol_signed = "ARC_SIGNED";
try_fallback = false;
use_domain = "header";
use_esld = true;
use_redis = true;
key_prefix = "DKIM_ARC_KEYS";

enabled = true;
```

TODO
====

- Define more LDAP options
- Config file for settings

Feedback is welcome and I invite you to help.
