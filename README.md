# Auth Service

This Flask-based service manages authentication tokens within an internal network. Security precautions are in place to block direct external access, while services within a secured private network can interface with the system.

## Features

### Admin Interface
Accessible via the `/admin` endpoint, this web interface allows for the management of request tokens.

#### Creating Request Tokens
Administrators can generate request tokens by providing:
- **Client Name**: A name for the user or system.
- **Request Expiration**: The expiration time for the request. Defaults to 24 hours from creation.
- **Access Expiration**: Period for which access is valid. Defaults to one year, or can be set to unlimited.
- **Host**: The hostname of the allowed service.

This information is stored with additional metadata such as creation date, redemption status, and a unique identifier (UID).

#### Managing Tokens
The admin interface displays outstanding request tokens and active authentication tokens. Admins can delete or modify tokens and manage request/access expiration settings.

### Authorization Endpoints
Available at `/auth`. Supports two types of operations:

#### Token Redemption
- Requires `krets_request_token=<uid>` and `X-Original-Host=<str host>`.
- Validates the token against the database. If the request is valid and unredeemed within its expiration limits, marks it redeemed and generates an `auth_token`.
- Response includes a new `Set-Cookie: krets_auth_token`.

#### Access
- Utilizes `Cookie: krets_auth_token=<token>` and `X-Original-Host=<str host>`.
- Confirms the validity of the `auth_token` and matches the host name.
- Updates `last_use` and performs garbage collection by expiring and removing used request tokens.
- Renews token if `renew_after` has passed.

## Usage

### Requirements
- Flask
- Flask-SQLAlchemy

### Running the Application
1. Set up the environment and install dependencies.
2. Initialize the database.
3. Run the application with `python app.py`.

### Code Structure
- **Models**: RequestToken, AuthToken
- **Admin Routes**: Viewing and managing tokens
- **Auth Routes**: Handling redemption and access logic

The application script, `app.py`, contains complete implementation details of the application logic, including routes and database operations. Ensure the system clock is synchronized for accurate token expiration handling.