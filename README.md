# Nginx Token Auth

This a Flask service that provides token-based `auth_request` for nginx reverse-proxy servers.

The service should only be accessible within a secure network. It will determine access ("yay" or "nay") based on authentication requests or tokens. Auth tokens are stored in a cookie, `krets_auth_token`, and will be periodically rotated.

## Process Overview

1. A request token is generated for a specific `host` intended to access the nginx proxy.
2. The client connects using `http(s)://{host}/?krets_auth_request={token}`.
3. The auth service validates the request token, and if valid, exchanges it for a new auth token that is stored on the client.
4. Subsequent requests with the valid cookie pass through the nginx proxy without interruption.

## Admin Interface

For my convenience, there’s an admin interface for generating tokens. It's presumed to be secured behind a VPN or private network, so no authentication is included. It provides a simple way to add and expire tokens.

## Docker Compose

This repo includes a functional Docker Compose setup for a single test site. `dummysite.example.com`. Adjust your system `hosts` file or use a real DNS entry for testing.