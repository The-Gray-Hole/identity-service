# identity-service

An api service for user, role and permission management.
This package has only one class named IdentityService. To get your identity service ready you only have to instatiate this class and call the route() and start() methods in that order.
It will create default permissions, role and one admin user for management.

Example
```javascript
var identity = require('identity-service');

let db_uri = process.env.DB_URI;
let port = process.env.PORT;
let secret = process.env.IDENTITY_SECRET;
let cors_withe_list = process.env.CORS_W_LIST ? process.env.CORS_W_LIST.split(",") : [];
let admin_username = process.env.ADMIN_USERNAME;
let admin_email = process.env.ADMIN_EMAIL;
let admin_secret = process.env.ADMIN_PW;
let free_actions = process.env.FREE_ACTIONS ? process.env.FREE_ACTIONS.split(",") : ["FINDALL", "FINDONE"];
let name = process.env.APP_NAME;

var tgh_identity = new identity.IdentityService(
    db_uri,
    secret,
    cors_withe_list,
    admin_username,
    admin_email,
    admin_secret,
    port,
    free_actions,
    name
);

tgh_identity.route();
tgh_identity.start();

identity.route(function(resource, action, data) {
    switch(resource) {
        case identity.Resources.Permissions:
            console.lg(`Performed action ${action} over Permissions with result data ${data}`);
            break;
        case identity.Resources.Roles:
            console.lg(`Performed action ${action} over Roles with result data ${data}`);
            break;
        case identity.Resources.Users:
            console.lg(`Performed action ${action} over Users with result data ${data}`);
            break;
    }
});

identity.start();
```

## Endpoints

### Global endpoints

```
/permissions
/roles
/users
```

### Specific endpoints

```
/permissions/:permissionId
/roles/:roleId
/users/:userId
```

### Actions

The three endpoints allow you to perform next actions:

#### For Global endpoints

```
CREATE -> POST
FINDALL -> GET
```

#### For Specific endpoints

```
FINDONE -> GET
UPDATE -> PUT
DELETE -> DELETE
```

### Payloads

This payloads are valid for create and update actions.

```javascript
permission_payload = {
    title: String
}

role_payload = {
    title: String,
    permissions: Array<String> // The ids of permissions included in the role
}

user_payload = {
    username: String,
    email: String,
    password: String,
    roles: Array<String>  // The id of roles the user has
}
```

### Authentication

In order to authenticate your requests you must provide an 'access-token' header
with your token.

To generate your token you should login using the admin user created or other with the required permissions.

## Access endpoints

This endpoints are used to login an user and check if an user has an specific permission

### Login endpoint.

This endpoint will response with a session token if credentials are valid.
This token has encripted information relative to roles the user has.

```
/login -> POST
```

```javascript
payload = {
    username: String,
    password: String,
}
```

### Check permission endpoint.

This endpoint will response with a 200 status if the token owner role has the specified permission

```
/check_permission -> POST

headers: access-token // The token obtained with the login endpoint
```

```javascript
payload = {
    permission: String, // permission id
}
```