"""
arc

Copyright (c) 2017 R.N.S.
"""

import hashlib
import os
import sys
import time
from html import escape
from wsgiref.simple_server import make_server

import ldap
import ldap.sasl
import ldapurl
import memcache
import redis

# -- Configuration -------------------------------------------------------------

LDAP_URL = "ldap://db.roessner-net.de/" \
           "ou=dkim,ou=it,dc=roessner-net,dc=de??" \
           "sub"
LDAP_TLS_CERT = "/etc/ssl/certs/mx.roessner-net.de.pem"
LDAP_TLS_KEY = "/etc/ssl/private/mx.roessner-net.de.key.pem"

MC_URL = "127.0.0.1:11211"
MC_TTL = 3600

REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_HMNAME = "ARC_KEYS"

DEBUG = True

# ------------------------------------------------------------------------------

__version__ = '2017.11.1'
__author__ = "Christian Roessner <c@roessner.co>"
__copyright__ = "Copyright (c) 2017 R.N.S."

if not os.path.exists(LDAP_TLS_CERT):
    raise Exception("File not found: {}".format(LDAP_TLS_CERT))
if not os.path.exists(LDAP_TLS_KEY):
    raise Exception("File not found: {}".format(LDAP_TLS_KEY))

# Set up LDAP options
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
ldap.set_option(ldap.OPT_X_TLS_CIPHER_SUITE, 'TLSv1.2')
ldap.set_option(ldap.OPT_X_TLS_CERTFILE, LDAP_TLS_CERT)
ldap.set_option(ldap.OPT_X_TLS_KEYFILE, LDAP_TLS_KEY)
auth_tokens = ldap.sasl.external("")


# noinspection SqlNoDataSourceInspection
def application(environ, start_response):
    # HTTP status codes
    stat_ok = "200 OK"
    stat_not_modified = "304 Not Modified"
    stat_err = "500 Internal Server Error"

    response_body = b""
    response_headers = list()

    status = stat_ok

    request_method = environ['REQUEST_METHOD']
    request_method = escape(request_method)

    mc = memcache.Client([MC_URL], debug=0)
    if not mc:
        print("memcache: error", file=sys.stderr)
    rd = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
    if not rd:
        print("redis: error", file=sys.stderr)

    # Force GET requests for each mail
    timestamp = time.time()
    date_fmt = '%a, %d %b %Y %H:%M:%S GMT'
    past = time.strftime(date_fmt, time.gmtime(timestamp - 3600.0))
    now = time.strftime(date_fmt, time.gmtime(timestamp))

    if request_method == "DELETE":
        client = environ['REMOTE_ADDR']
        mc_key = "arc_{}".format(client)

        if mc:
            mc.delete(mc_key)
            if DEBUG:
                print("memcache: key '{}' deleted".format(mc_key))

        response_headers = [('Date', now)]
        start_response(status, response_headers)

        return [response_body]

    # Rspamd result map
    result_map_l = list()
    result_map = b''

    map_refreshed = False

    # Connect to LDAP
    url_parts = ldapurl.LDAPUrl(LDAP_URL)
    con_string = "{}://{}".format(url_parts.urlscheme, url_parts.hostport)
    con = ldap.initialize(con_string)
    try:
        con.start_tls_s()
        con.sasl_interactive_bind_s('', auth_tokens)
    except Exception as ldap_error:
        print("ldap: cannot connect to LDAP server: {}".format(ldap_error),
              file=sys.stderr)

    if con:
        # Get DKIMDomains and DKIMSelector attributes
        filterstr = "(objectClass=DKIM)"
        search_attrs = ['DKIMDomain', 'DKIMSelector', 'DKIMKey']
        rid_dmn = con.search(url_parts.dn,
                             url_parts.scope,
                             filterstr,
                             search_attrs)

        raw_result_dmn = con.result(rid_dmn, True, 60)
        if not raw_result_dmn[0]:
            print("ldap: timeout for search operation", file=sys.stderr)
            con.abandon(rid)
            status = stat_not_modified
        else:
            keys_ldap = list()
            for entry in raw_result_dmn[1]:
                attrs = entry[1]
                if 'DKIMDomain' in attrs:
                    domain = attrs['DKIMDomain'][0]
                else:
                    continue
                selector = attrs['DKIMSelector'][0]
                rsa_key = attrs['DKIMKey'][0]

                # Auto sync RSA keys from LDAP to Redis
                redis_key = b'.'.join([selector, domain])
                keys_ldap.append(redis_key)
                if rd:
                    redis_result = rd.hmget(REDIS_HMNAME, redis_key)
                    if redis_result[0]:
                        if DEBUG:
                            print(
                                "redis: RSA key found for {} length={}".format(
                                    redis_key, len(redis_result[0])))
                    else:
                        rd.hmset(REDIS_HMNAME, {redis_key: rsa_key})
                        if DEBUG:
                            print("redis: RSA key added for {}".format(
                                redis_key))

                # Add record to map
                result_map_l.append(domain + b'\t' + selector + b'\r\n')

            if rd:
                # Remove orphaned redis keys
                keys_redis = rd.hkeys(REDIS_HMNAME)
                for redis_key in iter(keys_redis):
                    if redis_key not in keys_ldap:
                        rd.hdel(REDIS_HMNAME, redis_key)
                        if DEBUG:
                            print("redis: RSA key removed for {}".format(
                                redis_key))

            # Create final result map for HTTP response
            result_map = b''.join(result_map_l)
            result_map_ldap_hash = hashlib.sha256(result_map).hexdigest()
            if DEBUG:
                print("result_map_ldap_hash={}".format(result_map_ldap_hash))

            client = environ['REMOTE_ADDR']
            mc_key = "arc_{}".format(client)
            if mc:
                mc_value = mc.get(mc_key)
                if mc_value:
                    if DEBUG:
                        print("mc_value={}".format(mc_value))
                    if mc_value != result_map_ldap_hash:
                        map_refreshed = True
                    if not map_refreshed:
                        if DEBUG:
                            print("memcache: ARC selector map touched")
                        mc.touch(mc_key, time=MC_TTL)
                    else:
                        if DEBUG:
                            print("memcache: ARC selector map changed")
                        mc.replace(mc_key, result_map_ldap_hash, time=MC_TTL)
                else:
                    if DEBUG:
                        print("memcache: ARC selector map created")
                    mc.set(mc_key, result_map_ldap_hash, time=MC_TTL)
                    map_refreshed = True
            else:
                status = stat_err

        # Closing LDAP connection
        con.unbind_s()

    else:
        status = stat_err

    if request_method == "HEAD":
        response_body = b'\r\n'
        if map_refreshed:
            response_headers = [('Date', now), ('Last-Modified', past)]
        else:
            status = stat_not_modified
            response_headers = [('Date', now)]

    elif request_method == "GET":
        response_body = result_map

        body_len = str(len(response_body))

        response_headers = [('Date', now),
                            ('Content-Type', 'text/plain'),
                            ('Content-Length', body_len)]

    else:
        status = stat_err

    start_response(status, response_headers)

    return [response_body]


if __name__ == "__main__":
    httpd = make_server('localhost', 8080, application)
    httpd.handle_request()

# vim: expandtab ts=4 sw=4
