import { MongoModel } from 'rest-mongoose';
import { MongoController, valid_actions } from 'rest-mongoose';
import { MongoRouter } from 'rest-mongoose';
import { urlencoded, json } from 'body-parser';
import { Types, connect } from 'mongoose';
import { Auth } from 'rest-mongoose';
import { verify } from 'jsonwebtoken';
import { sign } from 'jsonwebtoken';
import { compareSync, hashSync } from 'bcryptjs';
import { requests } from 'sinon';

var cors = require('cors');

var validateEmail = function(email: string) {
    var re = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    return re.test(email)
};

interface MainDecoded {
    permissions: Array<string>,
    role: Array<string>,
    user: Array<string>,
    exp: number,
    iat: number
}

interface SessDecoded {
    duration: string,
    username: string,
    useremail: string,
    permissions: Array<string>,
    uid: string,
    roles: string,
    exp: number,
    iat: number
}

interface RouterCallback {
    (resource: Resources, action: string, data: any): void;
}

export enum Resources {
    TenantStatus = 1,
    Tenant,
    Permission,
    Role,
    UserStatus,
    User
}

export class IdentityService {
    private _permission_model: MongoModel;
    private _role_model: MongoModel;
    private _tenant_status_model: MongoModel;
    private _tenant_model: MongoModel;
    private _user_status_model: MongoModel;
    private _user_model: MongoModel;

    private _permission_ctl: MongoController;
    private _role_ctl: MongoController;
    private _tenant_status_ctl: MongoController;
    private _tenant_ctl: MongoController;
    private _user_status_ctl: MongoController;
    private _user_ctl: MongoController;

    private _permission_router: MongoRouter;
    private _role_router: MongoRouter;
    private _tenant_status_router: MongoRouter;
    private _tenant_router: MongoRouter;
    private _user_status_router: MongoRouter;
    private _user_router: MongoRouter;

    private _permission_auth: Auth;
    private _role_auth: Auth;
    private _tenant_status_auth: Auth;
    private _tenant_auth: Auth;
    private _user_status_auth: Auth;
    private _user_auth: Auth;

    private _app: any;
    private _app_name: string;
    private _port: Number;
    private _identity_secret: string;

    private _admin_username: string;
    private _admin_email: string;
    private _admin_password: string;

    constructor(db_url: string,
                identity_secret: string,
                cors_white_list: Array<string>,
                admin_username: string,
                admin_email: string,
                admin_password: string,
                port?: Number,
                free_actions?: Array<string>,
                app_name?: string) {
        
        //########## Defining Models ##################
        this._tenant_status_model = new MongoModel(
            "tstatus",
            {
                title: {
                    type: String,
                    unique: true,
                    required: true
                }
            },
            true
        )

        this._tenant_model = new MongoModel(
            "tenant",
            {
                tenantname: {
                    type: String,
                    unique: true,
                    required: true
                },
                status: [{
                    type: Types.ObjectId,
                    ref: 'Tstatus'
                }]
            },
            true
        )

        this._permission_model = new MongoModel(
            "permission",
            {
                title: {
                    type: String,
                    required: true
                },
                tenant: {
                    type: Types.ObjectId,
                    ref: 'Tenant',
                    required: true
                }
            },
            true,
            [],
            [
                {
                    fields: { title: 1, tenant: 1 },
                    options: { unique: true }
                }
            ]
        );

        this._role_model = new MongoModel(
            "role",
            {
                title: {
                    type: String,
                    required: true
                },
                permissions: [{
                    type: Types.ObjectId,
                    ref: 'Permission'
                }],
                tenant: {
                    type: Types.ObjectId,
                    ref: 'Tenant',
                    required: true
                }
            },
            true,
            [],
            [
                {
                    fields: { title: 1, tenant: 1 },
                    options: { unique: true }
                }
            ]
        );

        this._user_status_model = new MongoModel(
            "ustatus",
            {
                title: {
                    type: String,
                    required: true
                },
                tenant: {
                    type: Types.ObjectId,
                    ref: 'Tenant',
                    required: true
                }
            },
            true,
            [],
            [
                {
                    fields: { title: 1, tenant: 1 },
                    options: { unique: true }
                }
            ]
        )

        this._user_model = new MongoModel(
            "user",
            {
                username: {
                    type: String,
                    required: true
                },
                email: {
                    type: String,
                    lowercase: true,
                    required: true,
                    validate: [validateEmail, 'Please fill a valid email address']
                },
                password: {
                    type: String,
                    required: true
                },
                roles: [{
                    type: Types.ObjectId,
                    ref: 'Role'
                }],
                status: [{
                    type: Types.ObjectId,
                    ref: 'Ustatus'
                }],
                tenant: {
                    type: Types.ObjectId,
                    ref: 'Tenant',
                    required: true
                }
            },
            true,
            ["password"],
            [
                {
                    fields: { username: 1, tenant: 1 },
                    options: { unique: true }
                },
                {
                    fields: { email: 1, tenant: 1 },
                    options: { unique: true }
                }
            ]
        );

        //########## Defining Controllers ##################
        this._tenant_status_ctl = new MongoController(
            this._tenant_status_model,
            valid_actions,
        );

        this._tenant_ctl = new MongoController(
            this._tenant_model,
            valid_actions,
        );

        this._permission_ctl = new MongoController(
            this._permission_model,
            valid_actions,
        );

        this._role_ctl = new MongoController(
            this._role_model,
            valid_actions,
        );

        this._user_status_ctl = new MongoController(
            this._user_status_model,
            valid_actions,
        );

        this._user_ctl = new MongoController(
            this._user_model,
            valid_actions,
        );

        //########## Defining Auths ##################
        this._tenant_status_auth = new Auth(
            this._tenant_status_model,
            async function(token: string, action: string, instance_id: string) {
                try {
                    var decoded = verify(token, identity_secret || "") as MainDecoded;
                    switch(action) {
                        case "FINDALL": case "FINDONE":
                            return decoded.permissions.includes("__read__tenant_stat");
                            break;
                        case "CREATE": case "UPDATE": case "DELETE":
                            return decoded.permissions.includes("__write__tenant_stat");
                            break;
                    }
                } catch(err) {
                    return false;
                }
            },
            free_actions || []
        );

        this._tenant_auth = new Auth(
            this._tenant_model,
            async function(token: string, action: string, instance_id: string) {
                try {
                    var decoded = verify(token, identity_secret || "") as MainDecoded;
                    switch(action) {
                        case "FINDALL": case "FINDONE":
                            return decoded.permissions.includes("__read__tenant");
                            break;
                        case "CREATE": case "UPDATE": case "DELETE":
                            return decoded.permissions.includes("__write__tenant");
                            break;
                    }
                } catch(err) {
                    return false;
                }
            },
            free_actions || []
        );

        this._permission_auth = new Auth(
            this._permission_model,
            async function(token: string, action: string, instance_id: string) {
                try {
                    var decoded = verify(token, identity_secret || "") as MainDecoded;
                    switch(action) {
                        case "FINDALL": case "FINDONE":
                            return decoded.permissions.includes("__read__permission");
                            break;
                        case "CREATE": case "UPDATE": case "DELETE":
                            return decoded.permissions.includes("__write__permission");
                            break;
                    }
                } catch(err) {
                    return false;
                }
            },
            free_actions || []
        );

        this._role_auth = new Auth(
            this._role_model,
            async function(token: string, action: string, instance_id: string) {
                try {
                    var decoded = verify(token, identity_secret || "") as MainDecoded;
                    switch(action) {
                        case "FINDALL": case "FINDONE":
                            return decoded.permissions.includes("__read__role");
                            break;
                        case "CREATE": case "UPDATE": case "DELETE":
                            return decoded.permissions.includes("__write__role");
                            break;
                    }
                } catch(err) {
                    return false;
                }
            },
            free_actions || []
        );

        this._user_status_auth = new Auth(
            this._user_status_model,
            async function(token: string, action: string, instance_id: string) {
                try {
                    var decoded = verify(token, identity_secret || "") as MainDecoded;
                    switch(action) {
                        case "FINDALL": case "FINDONE":
                            return decoded.permissions.includes("__read__user_stat");
                            break;
                        case "CREATE": case "UPDATE": case "DELETE":
                            return decoded.permissions.includes("__write__user_stat");
                            break;
                    }
                } catch(err) {
                    return false;
                }
            },
            free_actions || []
        );

        this._user_auth = new Auth(
            this._user_model,
            async function(token: string, action: string, instance_id: string) {
                try {
                    var decoded = verify(token, identity_secret || "") as MainDecoded;
                    switch(action) {
                        case "FINDALL": case "FINDONE":
                            return decoded.permissions.includes("__read__user");
                            break;
                        case "CREATE": case "UPDATE": case "DELETE":
                            return decoded.permissions.includes("__write__user");
                            break;
                    }
                } catch(err) {
                    return false;
                }
            },
            free_actions || []
        );

        //########## Creating the app ##################
        this._app_name = app_name || "My API";
        this._port = port || 8000;
        this._identity_secret = identity_secret;
        
        var corsOptions = {
          origin: function (origin: any, callback: any) {
            if (cors_white_list.includes(origin)) {
              callback(null, true);
            } else {
              callback(new Error(`Origin ${origin} is not allowed by CORS`));
            }
          }
        }

        this._app = require('express')();
        this._app.use(urlencoded({ extended: true }));
        this._app.use(json());
        this._app.use(cors_white_list.length == 0 ? cors() : cors(corsOptions));

        //########## Defining Routers ##################
        this._tenant_status_router = new MongoRouter(this._app, this._tenant_status_ctl, this._tenant_status_auth);
        this._tenant_router = new MongoRouter(this._app, this._tenant_ctl, this._tenant_auth);
        this._permission_router = new MongoRouter(this._app, this._permission_ctl, this._permission_auth);
        this._role_router = new MongoRouter(this._app, this._role_ctl, this._role_auth);
        this._user_status_router = new MongoRouter(this._app, this._user_status_ctl, this._user_status_auth);
        this._user_router = new MongoRouter(this._app, this._user_ctl, this._user_auth);

        this._admin_username = admin_username;
        this._admin_email = admin_email;
        this._admin_password = admin_password;

        //########## Connecting to database ##################
        connect(db_url, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useFindAndModify: false,
            useCreateIndex: true
        })
        .then( () => {
            console.log("Successfully connected to database");
        })
        .then( async () => {
            //########## Creating base tenant statuses ##################
            let __tenant_status = await this._tenant_status_model.model.find();
            __tenant_status = __tenant_status.map( (val: any) => {
                return val.title;
            });
            let new_tenant_status = [
                {
                    title: "__active"
                },
                {
                    title: "__inactive"
                }
            ]
            new_tenant_status = new_tenant_status.filter( (val: any) => {
                return !__tenant_status.includes(val.title);
            });
            await this._tenant_status_model.model.create(new_tenant_status);

            //########## Creating base tenants ##################
            let __tenants = await this._tenant_model.model.find();
            __tenants = __tenants.map( (val: any) => {
                return val.tenantname;
            });
            let __active_tstatus = await this._tenant_status_model.model.find();
            __active_tstatus = __active_tstatus
            .filter( (val: any) => {
                return val.title == "__active";
            })[0]._id;

            let new_tenants = [
                {
                    tenantname: "host",
                    status: __active_tstatus
                }
            ]
            new_tenants = new_tenants.filter( (val: any) => {
                return !__tenants.includes(val.tenantname);
            });
            await this._tenant_model.model.create(new_tenants);

            //########## Get Host tenant Id ##################
            let __host_tenant = await this._tenant_model.model.find();
            __host_tenant = __host_tenant
            .filter( (val: any) => {
                return val.tenantname == "host";
            })[0]._id;

            //########## Creating base permissions ##################
            let new_perms = [
                {
                    title: "__read__tenant_stat",
                    tenant: __host_tenant
                },
                {
                    title: "__write__tenant_stat",
                    tenant: __host_tenant
                },
                {
                    title: "__read__tenant",
                    tenant: __host_tenant
                },
                {
                    title: "__write__tenant",
                    tenant: __host_tenant
                },
                {
                    title: "__read__permission",
                    tenant: __host_tenant
                },
                {
                    title: "__write__permission",
                    tenant: __host_tenant
                },
                {
                    title: "__read__role",
                    tenant: __host_tenant
                },
                {
                    title: "__write__role",
                    tenant: __host_tenant
                },
                {
                    title: "__read__user_stat",
                    tenant: __host_tenant
                },
                {
                    title: "__write__user_stat",
                    tenant: __host_tenant
                },
                {
                    title: "__read__user",
                    tenant: __host_tenant
                },
                {
                    title: "__write__user",
                    tenant: __host_tenant
                }
            ];

            let __perms = await this._permission_model.model.find();
            __perms = __perms
            .filter( (val: any) => {
                return String(val.tenant) == String(__host_tenant);
            })
            .map( (val: any) => {
                return val.title;
            });

            new_perms = new_perms.filter( (val: any) => {
                return !__perms.includes(val.title);
            });

            await this._permission_model.model.create(new_perms);

            //########## Creating base roles ##################
            let __base_perms = await this._permission_model.model.find();
            __base_perms = __base_perms
            .filter( (val: any) => {
                return new_perms.map( (val1: any) => {
                    return val1.title;
                }).includes(val.title) &&
                String(val.tenant) == String(__host_tenant);
            })
            .map( (val: any) => {
                return val._id;
            });
            let new_roles = [
                {
                    title: "__identity_admin",
                    permissions : __base_perms,
                    tenant: __host_tenant
                }
            ];
            let __roles = await this._role_model.model.find();
            __roles = __roles.map( (val: any) => {
                return val.title;
            });
            new_roles = new_roles.filter( (val: any) => {
                return !__roles.includes(val.title);
            });
            await this._role_model.model.create(new_roles);

            //########## Creating base user statuses ##################
            let __user_status = await this._user_status_model.model.find();
            __user_status = __user_status
            .filter( (val: any) => {
                return String(val.tenant) == String(__host_tenant);
            })
            .map( (val: any) => {
                return val.title;
            });
            let new_user_status = [
                {
                    title: "__active",
                    tenant: __host_tenant
                },
                {
                    title: "__inactive",
                    tenant: __host_tenant
                }
            ]
            new_user_status = new_user_status.filter( (val: any) => {
                return !__user_status.includes(val.title);
            });
            await this._user_status_model.model.create(new_user_status);

            //########## Creating base users ##################
            let __active_ustatus = await this._user_status_model.model.find();
            __active_ustatus = __active_ustatus
            .filter( (val: any) => {
                return val.title == "__active" && String(val.tenant) == String(__host_tenant);
            })[0]._id;
            let __base_roles = await this._role_model.model.find();
            __base_roles = __base_roles
            .filter( (val: any) => {
                return new_roles.map( (val1: any) => {
                    return val1.title;
                }).includes(val.title) &&
                String(val.tenant) == String(__host_tenant);
            })
            .map( (val: any) => {
                return val._id;
            });
            let __users = await this._user_model.model.find();
            __users = __users
            .filter( (val: any) => {
                return String(val.tenant) == String(__host_tenant);
            })
            .map( (val: any) => {
                return val.username;
            });
            let new_users = [
                {
                    username: this._admin_username,
                    email : this._admin_email,
                    password: hashSync(this._admin_password, 10),
                    roles: __base_roles,
                    status: __active_ustatus,
                    tenant: __host_tenant
                }
            ];
            new_users = new_users.filter( (val: any) => {
                return !__users.includes(val.username);
            });
            this._user_model.model.create(new_users);
        })
        .catch( err => {
            console.log('Could not connect to the database. Exiting now...', err);
            process.exit();
        });
    }

    public route(resources_callback?: RouterCallback) {

        this._app.get('/', (request: any, response: any) => {
            request;
            response.json({
                message: `Welcome to test ${this._app_name}.`,
                endpoints: [
                    "/",
                    "/tstatuss",
                    "/tenants",
                    "/permissions",
                    "/roles",
                    "/ustatuss",
                    "/users",
                    "/tstatuss:tstatusid",
                    "/tenants/:tenantid",
                    "/permissions/permissionid:",
                    "/roles/:roleid",
                    "/ustatuss/:ustatusid",
                    "/users/:userid",
                ]
            });
        });

        this._app.post('/login', async (request: any, response: any) => {
            let user = await this._user_model.model.findOne({username: request.body.username}).exec();
            if(!user) {
                return response.status(400).send({message: "Invalid credentials"});
            }
            if(!compareSync(request.body.password, user.password)) {
                return response.status(400).send({message: "Invalid credentials"});
            }
            let perms = [];
            for(let i = 0; i < user.roles.length; i++) {
                let role = await this._role_model.model.findById(user.roles[i]);
                if(String(role.tenant) != String(user.tenant)) continue;
                for(let j = 0; j < role.permissions.length; j++) {
                    let p = await this._permission_model.model.findById(role.permissions[j]);
                    if(String(p.tenant) != String(user.tenant)) continue;
                    perms.push(p.title);
                }
            }
            let dur = request.body.token_duration ? request.body.token_duration : 24;
            let _session_token = sign({
                exp: Math.floor(Date.now() / 1000) + (dur * 60 * 60),
                duration: `${dur} h`,
                uid: user._id,
                username: user.username,
                useremail: user.email,
                permissions: perms
            }, this._identity_secret)

            response.status(200).send({
                session_token: _session_token
            });
        });

        this._app.post('/check_permission', async (request: any, response: any) => {
            let token = request.headers['access-token'];
            let permission = request.body.permission;
            if(!token) {
                return response.status(400).send({message: "Missing access token"});
            }
            try {
                let decoded = verify(token, this._identity_secret || "") as SessDecoded;
                if(decoded.permissions.includes(permission)) {
                    return response.status(200).send({
                        message: `The user ${decoded.username} has permission to ${permission}`,
                        data: {
                            duration: decoded.duration,
                            uid: decoded.uid,
                            username: decoded.username,
                            useremail: decoded.useremail
                        }
                    });
                } else {
                    return response.status(400).send({message: "Access Denied"});
                }
            } catch(err) {
                return response.status(400).send({message: "Access Denied"});
            }
        });

        this._app.post('/get_uid', async (request: any, response: any) => {
            let token = request.headers['access-token'];
            if(!token) {
                return response.status(400).send({message: "Missing access token"});
            }
            try {
                let decoded = verify(token, this._identity_secret || "") as SessDecoded;
                if(decoded.uid) {
                    return response.status(200).send({
                        uid: decoded.uid
                    });
                } else {
                    return response.status(400).send({message: "Invalid Token"});
                }
            } catch(err) {
                return response.status(400).send({message: "Invalid Token"});
            }
        });

        this._tenant_status_router.route(function(action: string, data: any) {
            if(resources_callback) {
                resources_callback(Resources.TenantStatus, action, data);
            }
        });

        this._tenant_router.route(function(action: string, data: any) {
            if(resources_callback) {
                resources_callback(Resources.Tenant, action, data);
            }
        });

        this._permission_router.route(function(action: string, data: any) {
            if(resources_callback) {
                resources_callback(Resources.Permission, action, data);
            }
        });

        this._role_router.route(function(action: string, data: any) {
            if(resources_callback) {
                resources_callback(Resources.Role, action, data);
            }
        });

        this._user_status_router.route(function(action: string, data: any) {
            if(resources_callback) {
                resources_callback(Resources.UserStatus, action, data);
            }
        });

        this._user_router.route(function(action: string, data: any) {
            if(resources_callback) {
                resources_callback(Resources.User, action, data);
            }
        });
    }

    public start() {
        this._app.listen(this._port, () => {
            console.log(`Server is listening on port ${String(this._port)}`);
        });
    }
}
