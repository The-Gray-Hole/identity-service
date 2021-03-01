import { MongoModel } from 'rest-mongoose';
import { MongoController } from 'rest-mongoose';
import { MongoRouter } from 'rest-mongoose';
import { Auth } from 'rest-mongoose';
import { valid_actions } from 'rest-mongoose';

import { urlencoded, json } from 'body-parser';
import { connect } from 'mongoose';

import { create_initial_data } from './base_data';
import { get_tstatus_model } from './base_models';
import { get_tenant_model } from './base_models';
import { get_permission_model } from './base_models';
import { get_role_model } from './base_models';
import { get_ustatus_model } from './base_models';
import { get_user_model } from './base_models';
import { get_tstatus_auth } from './base_auths';
import { get_tenant_auth } from './base_auths';
import { get_permission_auth } from './base_auths';
import { get_role_auth } from './base_auths';
import { get_ustatus_auth } from './base_auths';
import { get_user_auth } from './base_auths';
import { TenantLimits } from './base_auths';
import { get_root } from './base_routes';
import { get_login } from './base_routes';
import { get_check_user_perm } from './base_routes';
import { get_check_user_status } from './base_routes';
import { get_resources_conf } from './base_routes';
import { get_tstatus_callback } from './routers_callbacks';
import { get_tenant_callback } from './routers_callbacks';
import { get_perm_callback } from './routers_callbacks';
import { get_role_callback } from './routers_callbacks';
import { get_ustatus_callback } from './routers_callbacks';
import { get_user_callback } from './routers_callbacks';

var cors = require('cors');

export { TenantLimits } from './base_auths';

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

    private _resources_config: any;
    private _tenant_limits: TenantLimits;

    constructor(db_url: string,
                identity_secret: string,
                cors_white_list: Array<string>,
                admin_username: string,
                admin_email: string,
                admin_password: string,
                resources_config: any,
                tenant_limits: TenantLimits,
                port?: Number,
                free_actions?: Array<string>,
                app_name?: string) {

        this._identity_secret = identity_secret;
        this._resources_config = resources_config;
        this._tenant_limits = tenant_limits;

        //########## Defining Models ##################
        this._tenant_status_model = get_tstatus_model();
        this._tenant_model = get_tenant_model();
        this._permission_model = get_permission_model();
        this._role_model = get_role_model();
        this._user_status_model = get_ustatus_model();
        this._user_model = get_user_model();

        //########## Defining Controllers ##################
        this._tenant_status_ctl = new MongoController(this._tenant_status_model, valid_actions);
        this._tenant_ctl = new MongoController(this._tenant_model, valid_actions);
        this._permission_ctl = new MongoController(this._permission_model, valid_actions);
        this._role_ctl = new MongoController(this._role_model, valid_actions);
        this._user_status_ctl = new MongoController(this._user_status_model, valid_actions);
        this._user_ctl = new MongoController(this._user_model, valid_actions);

        //########## Defining Auths ##################
        this._tenant_status_auth = get_tstatus_auth(this._tenant_status_model, this._identity_secret, free_actions);
        this._tenant_auth = get_tenant_auth(this._tenant_model, this._identity_secret, free_actions);
        this._permission_auth = get_permission_auth(this._permission_model, this._tenant_model, this._identity_secret, this._tenant_limits, free_actions);
        this._role_auth = get_role_auth(this._role_model, this._tenant_model, this._permission_model, this._identity_secret, this._tenant_limits, free_actions);
        this._user_status_auth = get_ustatus_auth(this._user_status_model, this._tenant_model, this._identity_secret, this._tenant_limits, free_actions);
        this._user_auth = get_user_auth(this._user_model, this._tenant_model, this._role_model, this._user_status_model, this._identity_secret, this._tenant_limits, free_actions);

        //########## Creating the app ##################
        this._app_name = app_name || "My API";
        this._port = port || 8000;
        
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
            //########## Creating base data ##################
            create_initial_data(
                this._tenant_status_model,
                this._tenant_model,
                this._permission_model,
                this._role_model,
                this._user_status_model,
                this._user_model,
                this._admin_username,
                this._admin_email,
                this._admin_password
            ).catch( err => {
                console.log('Could not create initial data. Exiting now...', err);
                process.exit();
            });
        })
        .catch( err => {
            console.log('Could not connect to the database. Exiting now...', err);
            process.exit();
        });
    }

    public route() {

        this._app.get('/', get_root(this._app_name));
        this._app.post('/login', get_login(this._user_model, this._role_model, this._permission_model, this._user_status_model, this._tenant_status_model, this._tenant_model, this._identity_secret));
        this._app.post('/check/user/permission', get_check_user_perm(this._identity_secret));
        this._app.post('/check/user/status', get_check_user_status(this._identity_secret));
        this._app.get('/resources_config', get_resources_conf(this._tenant_model, this._identity_secret, this._resources_config));

        this._tenant_status_router.route(get_tstatus_callback());
        this._tenant_router.route(get_tenant_callback());
        this._permission_router.route(get_perm_callback(this._tenant_model, this._identity_secret));
        this._role_router.route(get_role_callback(this._tenant_model, this._identity_secret));
        this._user_status_router.route(get_ustatus_callback(this._tenant_model, this._identity_secret));
        this._user_router.route(get_user_callback(this._tenant_model, this._identity_secret));
    }

    public start() {
        this._app.listen(this._port, () => {
            console.log(`Server is listening on port ${String(this._port)}`);
        });
    }
}
