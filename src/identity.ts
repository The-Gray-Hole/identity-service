import { MongoModel } from 'rest-mongoose';
import { MongoController, valid_actions } from 'rest-mongoose';
import { MongoRouter } from 'rest-mongoose';
import { urlencoded, json } from 'body-parser';
import { Types, connect } from 'mongoose';
import { Auth } from 'rest-mongoose';
import { verify } from 'jsonwebtoken';

var validateEmail = function(email: string) {
    var re = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    return re.test(email)
};

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

    private _basic_auth: Auth;

    private _app: any;
    private _port: Number;

    constructor(db_url: string, port?: Number, free_actions?: Array<String>, app_name?: string) {
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

        this._basic_auth = new Auth(
            function(token: string, action: string) {
                try {
                    var decoded = verify(token, process.env.IDENTITY_SECRET || "");
                    console.log(process.env.IDENTITY_SECRET);
                    return decoded == process.env.IDENTITY_SECRET;
                } catch(err) {
                    return false;
                }
            },
            valid_actions
        );

        this._app = require('express')();
        this._app.use(urlencoded({ extended: true }));
        this._app.use(json());
        this._app.get('/', (request: any, response: { json: (arg0: { message: string; }) => void; }) => {
            request;
            response.json({"message": `Welcome to test ${app_name || "My API"}.`});
        });
        this._port = port || 8000;

        this._permission_router = new MongoRouter(this._app, this._permission_ctl, this._basic_auth);
        this._role_router = new MongoRouter(this._app, this._role_ctl, this._basic_auth);
        this._user_router = new MongoRouter(this._app, this._user_ctl, this._basic_auth);

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
