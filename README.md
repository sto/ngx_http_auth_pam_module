# ngx_http_auth_pam_module

## Nginx module to use PAM for simple http authentication

### Compilation

When compiling from source build as usual adding the ``--add-module`` option:

	./configure --add-module=$PATH_TO_MODULE

or if you want to build the module as dynamic use the ``--add-dynamic-module``
option.

If you are using a Debian GNU/Linux distribution install the ``nginx-full``
package; the module has been included in the debian package since version
``1.1.6-1``, so it is available on all stable distributions since the *wheezy*
release.

### Configuration

The module only has two directives:

- ``auth_pam``: This is the http authentication realm. If given the value
  ``off`` the module is disabled (needed when we want to override the value
  set on a lower-level directive).

- ``auth_pam_service_name``: this is the PAM service name and by default it is
  set to ``nginx``.

### Examples

To protect everything under ``/secure`` you will add the following to the
``nginx.conf`` file:

	location /secure {
	    auth_pam              "Secure Zone";
	    auth_pam_service_name "nginx";
	}

Note that the module runs as the web server user, so the PAM modules used must
be able to authenticate the users without being root; that means that if you
want to use the ``pam_unix.so`` module to autenticate users you need to let the
web server user to read the ``/etc/shadow`` file if that does not scare you (on
Debian like systems you can add the ``www-data`` user to the ``shadow`` group).

As an example, to authenticate users against an LDAP server (using the
``pam_ldap.so`` module) you will use an ``/etc/pam.d/nginx`` like the
following:

	auth    required     /lib/security/pam_ldap.so
	account required     /lib/security/pam_ldap.so

If you also want to limit the users from LDAP that can authenticate you can
use the ``pam_listfile.so`` module; to limit who can access resources under
``/restricted`` add the following to the ``nginx.conf`` file:

	location /restricted {
	    auth_pam              "Restricted Zone";
	    auth_pam_service_name "nginx_restricted";
	}

Use the following ``/etc/pam.d/nginx_restricted`` file:

	auth    required     /lib/security/pam_listfile.so onerr=fail item=user \
	                     sense=allow file=/etc/nginx/restricted_users
	auth    required     /lib/security/pam_ldap.so
	account required     /lib/security/pam_ldap.so

And add the users allowed to authenticate to the ``/etc/nginx/restricted_users``
(remember that the web server user has to be able to read this file).

### PAM Environment

If you want use the ``pam_exec.so`` plugin for request based authentication the
module can add to the PAM environment the ``HOST`` and ``REQUEST`` variables if
you set the ``auth_pam_set_pam_env`` flag::

	location /pam_exec_protected {
	  auth_pam              "Exec Zone";
	  auth_pam_service_name "nginx_exec";
	  auth_pam_set_pam_env  on;
	}

With this configuration if you access an URL like:

	http://localhost:8000/pam_exec_protected/page?foo=yes&bar=too

the PAM environment will include the following variables:

	HOST=localhost:8000
	REQUEST=GET /pam_exec_protected/page?foo=yes&bar=too HTTP/1.1

You may use this information for request based authentication.
You need a recent pam release (>= version 1.0.90) to expose environment
variables to pam_exec.
