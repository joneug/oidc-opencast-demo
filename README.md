# OpenID Connect for Opencast Demo

This repository contains a proof-of-concept demonstrating using [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) with [Opencast](https://opencast.org). Here, [Keycloak](https://www.keycloak.org) is used as a local identity provider. The OpenID Connect authentication flow is provided by the [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) service in front of Opencast. Additionally, [NGINX](https://www.nginx.com) is used as a reverse proxy. The NGINX `auth_request` directive ensures that all requests to Opencast are authenticated using OpenID Connect. The handling of ID tokens issued by Keycloak is implemented in the `security-jwt` module.

## Building

Download and build Opencast with the additional `security-jwt` module:

```
make build
```

## Running

Update your DNS settings (e.g. in the `/etc/hosts` file) so that the following domain names point to your local host:

* admin.opencast.local
* oauth2-proxy.opencast.local
* keycloak.opencast.local

Start all the required services:

```
make start
```

After a while Opencast should come up. Go to [admin.opencast.local](http://admin.opencast.local). Click on "Sign in with Keycloak" and authenticate using `admin@exmaple.com` and `password`. You should be redirected to the Admin UI.

Stop all services:

```
make stop
```
