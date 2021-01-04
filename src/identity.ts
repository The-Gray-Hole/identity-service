import { MongoModel } from 'rest-mongoose';
import { MongoController, valid_actions } from 'rest-mongoose';
import { MongoRouter } from 'rest-mongoose';
import { urlencoded, json } from 'body-parser';
import { Types, connect } from 'mongoose';
import { Auth } from 'rest-mongoose';
import { verify } from 'jsonwebtoken';

var cors = require('cors');

var validateEmail = function(email: string) {
    var re = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    return re.test(email)
};

interface Idecoded {
    permission: Array<string>,
    role: Array<string>,
    user: Array<string>,
    exp: number,
    iat: number
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
    private _port: Number;

    constructor(db_url: string,
                identity_secret: string,
                cors_white_list: Array<string>,
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
                    trim: true,
                    lowercase: true,
                    unique: true,
                    required: true,
                    validate: [validateEmail, 'Please fill a valid email address'],
                    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
                },
                password: {
                    type: String,
                    required: true
                },
                role: {
                    type: Types.ObjectId,
                    ref: 'Role'
                }
            },
            true
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
            function(token: string, action: string) {
                try {
                    var decoded = verify(token, identity_secret || "") as Idecoded;
                    return decoded.permission.includes(action);
                } catch(err) {
                    return false;
                }
            },
            free_actions || []
        );

        this._role_auth = new Auth(
            function(token: string, action: string) {
                try {
                    var decoded = verify(token, identity_secret || "") as Idecoded;
                    return decoded.role.includes(action);
                } catch(err) {
                    return false;
                }
            },
            free_actions || []
        );

        this._user_auth = new Auth(
            function(token: string, action: string) {
                try {
                    var decoded = verify(token, identity_secret || "") as Idecoded;
                    return decoded.user.includes(action);
                } catch(err) {
                    return false;
                }
            },
            free_actions || []
        );

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
        this._app.use(cors(corsOptions));

        this._app.get('/', (request: any, response: any) => {
            request;
            response.json({
                "message": `Welcome to test ${app_name || "My API"}.`
            });
        });
        this._port = port || 8000;

        this._permission_router = new MongoRouter(this._app, this._permission_ctl, this._permission_auth);
        this._role_router = new MongoRouter(this._app, this._role_ctl, this._role_auth);
        this._user_router = new MongoRouter(this._app, this._user_ctl, this._user_auth);

        connect(db_url, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useFindAndModify: false,
            useCreateIndex: true
        })
        .then( () => {
            console.log("Successfully connected to database");    
        })
        .catch( err => {
            console.log('Could not connect to the database. Exiting now...', err);
            process.exit();
        });
    }

    public route() {
        this._permission_router.route();
        this._role_router.route();
        this._user_router.route();
    }

    public start() {
        this._app.listen(this._port, () => {
            console.log(`Server is listening on port ${String(this._port)}`);
        });
    }
}
