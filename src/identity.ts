import { MongoModel } from 'rest-mongoose';
import { MongoController, valid_actions } from 'rest-mongoose';
import { MongoRouter } from 'rest-mongoose';
import { urlencoded, json } from 'body-parser';
import { Types, connect } from 'mongoose';
import { Auth } from 'rest-mongoose';
import { verify } from 'jsonwebtoken';
import { sign } from 'jsonwebtoken';
import { compareSync, hashSync } from 'bcryptjs';

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
    uid: string,
    roles: string,
    exp: number,
    iat: number
}

interface RouterCallback {
    (resource: Resources, action: string, data: any): void;
}

export enum Resources {
    Permissions = 1,
    Roles,
    Users
}

export class IdentityService {
    private _permission_model: MongoModel;
    private _role_model: MongoModel;
    private _user_model: MongoModel;

    private _permission_ctl: MongoController;
    private _role_ctl: MongoController;
    private _user_ctl: MongoController;

    private _permission_router: MongoRouter;
    private _role_router: MongoRouter;
    private _user_router: MongoRouter;

    private _permission_auth: Auth;
    private _role_auth: Auth;
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
        this._permission_model = new MongoModel(
            "permission",
            {
                title: {
                    type: String,
                    unique: true,
                    required: true
                }
            },
            true
        );

        this._role_model = new MongoModel(
            "role",
            {
                title: {
                    type: String,
                    unique: true,
                    required: true
                },
                permissions: [{
                    type: Types.ObjectId,
                    ref: 'Permission'
                }]
            },
            true
        );

        this._user_model = new MongoModel(
            "user",
            {
                username: {
                    type: String,
                    unique: true,
                    required: true
                },
                email: {
                    type: String,
                    lowercase: true,
                    unique: true,
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
                }]
            },
            true,
            ["password"]
        );

        this._permission_ctl = new MongoController(
            this._permission_model,
            valid_actions,
        );

        this._role_ctl = new MongoController(
            this._role_model,
            valid_actions,
        );

        this._user_ctl = new MongoController(
            this._user_model,
            valid_actions,
        );

        this._permission_auth = new Auth(
            this._permission_model,
            async function(token: string, action: string, instance_id: string) {
                try {
                    var decoded = verify(token, identity_secret || "") as MainDecoded;
                    switch(action) {
                        case "FINDALL": case "FINDONE":
                            return decoded.permissions.includes("__permission__view");
                            break;
                        case "CREATE": case "UPDATE":
                            return decoded.permissions.includes("__permission__write");
                            break;
                        case "DELETE":
                            return decoded.permissions.includes("__permission__delete");
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
                            return decoded.permissions.includes("__role__view");
                            break;
                        case "CREATE": case "UPDATE":
                            return decoded.permissions.includes("__role__write");
                            break;
                        case "DELETE":
                            return decoded.permissions.includes("__role__delete");
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
                            return decoded.permissions.includes("__user__view");
                            break;
                        case "CREATE": case "UPDATE":
                            return decoded.permissions.includes("__user__write");
                            break;
                        case "DELETE":
                            return decoded.permissions.includes("__user__delete");
                            break;
                    }
                } catch(err) {
                    return false;
                }
            },
            free_actions || []
        );

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

        this._permission_router = new MongoRouter(this._app, this._permission_ctl, this._permission_auth);
        this._role_router = new MongoRouter(this._app, this._role_ctl, this._role_auth);
        this._user_router = new MongoRouter(this._app, this._user_ctl, this._user_auth);

        this._admin_username = admin_username;
        this._admin_email = admin_email;
        this._admin_password = admin_password;

        var ident_serv = this;

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
            // Creating base permissions
            let __perms = await ident_serv._permission_model.model.find();
            __perms = __perms.map( (val: any) => {
                return val.title;
            });
            let new_perms = [
                {
                    title: "__permission__view"
                },
                {
                    title: "__permission__write"
                },
                {
                    title: "__permission__delete"
                },
                {
                    title: "__role__view"
                },
                {
                    title: "__role__write"
                },
                {
                    title: "__role__delete"
                },
                {
                    title: "__user__view"
                },
                {
                    title: "__user__write"
                },
                {
                    title: "__user__delete"
                }
            ];

            new_perms = new_perms.filter( (val: any) => {
                return !__perms.includes(val.title);
            });

            ident_serv._permission_model.model.create(new_perms)
            .then( async () => {
                // Creating base roles
                let __roles = await ident_serv._role_model.model.find();
                __roles = __roles.map( (val: any) => {
                    return val.title;
                });
                __perms = await ident_serv._permission_model.model.find();
                __perms = __perms
                .filter( (val: any) => {
                    return (
                        val.title == "__permission__view" ||
                        val.title == "__permission__write" ||
                        val.title == "__permission__delete" ||
                        val.title == "__role__view" ||
                        val.title == "__role__write" ||
                        val.title == "__role__delete" ||
                        val.title == "__user__view" ||
                        val.title == "__user__write" ||
                        val.title == "__user__delete"
                    );
                })
                .map( (val: any) => {
                    return val._id;
                });
                let new_roles = [
                    {
                        title: "__identity_admin",
                        permissions : __perms
                    }
                ];
                new_roles = new_roles.filter( (val: any) => {
                    return !__roles.includes(val.title);
                });
                ident_serv._role_model.model.create(new_roles)
                .then( async () => {
                    let __users = await ident_serv._user_model.model.find();
                    __users = __users.map( (val: any) => {
                        return val.username;
                    });
                    __roles = await ident_serv._role_model.model.find();
                    __roles = __roles
                    .filter( (val: any) => {
                        return (val.title == "__identity_admin");
                    })
                    .map( (val: any) => {
                        return val._id;
                    });
                    let new_users = [
                        {
                            username: ident_serv._admin_username,
                            email : ident_serv._admin_email,
                            password: hashSync(ident_serv._admin_password, 10),
                            roles: __roles
                        }
                    ];
                    new_users = new_users.filter( (val: any) => {
                        return !__users.includes(val.username);
                    });
                    ident_serv._user_model.model.create(new_users);
                });
            });
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
                "message": `Welcome to test ${this._app_name}.`
            });
        });

        this._app.post('/login', async (request: any, response: any) => {
            let user = await this._user_model.model.findOne({username: request.body.username}).exec();
            if(!user) {
                return response.status(400).send({message: "Invalid user"});
            }
            if(!compareSync(request.body.password, user.password)) {
                return response.status(400).send({message: "Invalid password"});
            }
            let perms = [];
            for(let i = 0; i < user.roles.length; i++) {
                let role = await this._role_model.model.findById(user.roles[i]);
                for(let j = 0; j < role.permissions.length; j++) {
                    let p = await this._permission_model.model.findById(role.permissions[j]);
                    perms.push(p.title);
                }
            }
            let _session_token = sign({
                exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
                duration: "24 h",
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
                for(let i = 0; i < decoded.roles.length; i++) {
                    let role = await this._role_model.model.findOne({_id: decoded.roles[i]}).exec();
                    if(role.permissions.includes(permission)) {
                        let perm = await this._permission_model.model.findOne({_id: permission}).exec();
                        return response.status(200).send({
                            message: `The user ${decoded.username} has permission to ${perm.title}`,
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
                } 
                return response.status(400).send({message: "Access Denied"});
            } catch(err) {
                return response.status(400).send({message: "Access Denied"});
            }
        });

        this._permission_router.route(function(action: string, data: any) {
            if(resources_callback) {
                resources_callback(Resources.Permissions, action, data);
            }
        });
        this._role_router.route(function(action: string, data: any) {
            if(resources_callback) {
                resources_callback(Resources.Roles, action, data);
            }
        });
        this._user_router.route(function(action: string, data: any) {
            if(resources_callback) {
                resources_callback(Resources.Users, action, data);
            }
        });
    }

    public start() {
        this._app.listen(this._port, () => {
            console.log(`Server is listening on port ${String(this._port)}`);
        });
    }
}
