# identity-service

An api service for user, role and permission management.
This package has only one class named IdentityService. To get your identity service ready you only
have to instatiate this class and call the route() and start() methods in that order.

Example
```javascript
var identity = require('identity-service');

let db_uri = process.env.DB_URI; // A mongo database
let port = process.env.PORT;
let secret = process.env.IDENTITY_SECRET;
let cors_withe_list = process.env.CORS_W_LIST ? process.env.CORS_W_LIST.split(",") : [];
let free_actions = process.env.FREE_ACTIONS ? process.env.FREE_ACTIONS.split(",") : [];
let app_name = process.env.APP_NAME;

var identity = new identity.IdentityService(
    db_uri,
    secret,
    cors_withe_list,
    port,
    free_actions,
    app_name
    );

identity.route();
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
    role: String // The id of role the user has
}
```

### Authentication

In order to authenticate your requests you must provide an 'access-token' header
with your token.

To generate your token you should use JWT or equivalent as follows

```javascript
let jwt = require("jsonwebtoken");

let token = jwt.sign({
    exp: Math.floor(Date.now() / 1000) + (60 * 60), // This token will be valid for an hour
    permission: ["FINDALL", "FINDONE"], // This token will be valid only to ferform FINDALL and FINDONE actions over permission endpoints.
    role: ["FINDALL", "FINDONE", "CREATE", "UPDATE", "DELETE"], // This token will be valid to ferform all actions over role endpoints.
    user: [] // This token will be not valid to perform any action over user endpoints.
}, "secret-key"); // To make the token to be valid, this secret must match with the secret env variable in the API deploy

```

## Access endpoints

This endpoints are used to login an user and check if an user has an specific permission

### Login endpoint.

This endpoint will response with a session token if credentials are valid.

```
/login
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
/check_permission

headers: access-token // The token obtained with the login endpoint
```

```javascript
payload = {
    permission: String, // permission id
}
```