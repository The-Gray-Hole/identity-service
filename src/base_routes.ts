import { MongoModel } from 'rest-mongoose';
import { compareSync } from 'bcryptjs';
import { sign } from 'jsonwebtoken';
import { verify } from 'jsonwebtoken';

import { SessDecoded } from './base_auths';
import { PlanManager } from './plan_manager';

export function get_root
(
    app_name: string
)
{
    return async function(request: any, response: any) {
        response.status(200).send({
            message: `Welcome to test ${app_name}.`,
            endpoints: {
                root: {
                    __href: [
                        "/"
                    ],
                    actions: [
                        "GET"
                    ]
                },
                resources_all: {
                    __href: [
                        "/tstatuss",
                        "/tenants",
                        "/permissions",
                        "/roles",
                        "/ustatuss",
                        "/users"
                    ],
                    actions: [
                        "GET",
                        "POST"
                    ]
                },
                resources_one: {
                    __href: [
                        "/tstatuss/:tstatusid",
                        "/tenants/:tenantid",
                        "/permissions/permissionid:",
                        "/roles/:roleid",
                        "/ustatuss/:ustatusid",
                        "/users/:userid"
                    ],
                    actions: [
                        "GET",
                        "PUT",
                        "DELETE"
                    ]
                },
                auth: {
                    __href: [
                        "/login",
                        "/check/user/permission",
                        "/check/user/status"
                    ],
                    actions: [
                        "POST"
                    ]
                },
                config: {
                    __href: [
                        "/resources_config"
                    ],
                    actions: [
                        "GET"
                    ]
                }
            }
        });
    }
}

export function get_login
(
    user_model: MongoModel,
    role_model: MongoModel,
    perm_model: MongoModel,
    ustatus_model: MongoModel,
    tstatus_model: MongoModel,
    tenant_model: MongoModel,
    secret: string
)
{
    return async function(request: any, response: any) {
        try {
            let tenant = await tenant_model.model.findOne({tenantname: request.body.tenantname});
            let user = await user_model.model.findOne({username: request.body.username, tenant: tenant._id});
            if(!user) {
                return response.status(400).send({message: "Invalid credentials"});
            }
            if(!compareSync(request.body.password, user.password)) {
                return response.status(400).send({message: "Invalid credentials"});
            }
            let perms = [];
            let ustatuses = [];
            let tstatuses = [];
            for(let i = 0; i < user.roles.length; i++) {
                let role = await role_model.model.findById(user.roles[i]);
                for(let j = 0; j < role.permissions.length; j++) {
                    let p = await perm_model.model.findById(role.permissions[j]);
                    let t = await tenant_model.model.findById(p.tenant);
                    perms.push(`${p.title} in ${t.tenantname}`);
                }
            }
            for(let i = 0; i < user.status.length; i++) {
                let s = await ustatus_model.model.findById(user.status[i]);
                let t = await tenant_model.model.findById(s.tenant);
                ustatuses.push(`${s.title} in ${t.tenantname}`);
            }
            for(let i = 0; i < tenant.status.length; i++) {
                let s = await tstatus_model.model.findById(tenant.status[i]);
                tstatuses.push(`${s.title}`);
            }
            if(!tstatuses.includes("__active") || tstatuses.includes("__inactive")) {
                return response.status(400).send({message: "The user organization is not active"});
            }
            let _session_token = sign({
                exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
                duration: `24 h`,
                uid: user._id,
                username: user.username,
                useremail: user.email,
                permissions: perms,
                ustatus: ustatuses,
                tenant: user.tenant,
                tstatus: tstatuses,
            }, secret)

            response.status(200).send({
                session_token: _session_token
            });
        } catch {
            return response.status(400).send({message: "Invalid credentials"});
        }
    }
}

export function get_check_user_perm
(
    secret: string
)
{
    return async function(request: any, response: any) {
        let token = request.headers['access-token'];
            let permission = request.body.permission;
            let tenantname = request.body.tenantname;
            if(!token) {
                return response.status(400).send({message: "Missing access token"});
            }
            try {
                let decoded = verify(token, secret || "") as SessDecoded;
                if(decoded.permissions.includes(`${permission} in ${tenantname}`)) {
                    return response.status(200).send({
                        message: `The user ${decoded.username} has permission to ${permission} in ${tenantname}`,
                        data: decoded
                    });
                } else {
                    return response.status(400).send({message: "Access Denied"});
                }
            } catch(err) {
                return response.status(400).send({message: "Access Denied"});
            }
    }
}

export function get_check_user_status
(
    secret: string
)
{
    return async function(request: any, response: any) {
        let token = request.headers['access-token'];
            let status = request.body.status;
            let tenantname = request.body.tenantname;
            if(!token) {
                return response.status(400).send({message: "Missing access token"});
            }
            try {
                let decoded = verify(token, secret || "") as SessDecoded;
                if(decoded.ustatus.includes(`${status} in ${tenantname}`)) {
                    return response.status(200).send({
                        message: `The user ${decoded.username} has the status ${status} in ${tenantname}`,
                        data: decoded
                    });
                } else {
                    return response.status(400).send({message: "Access Denied"});
                }
            } catch(err) {
                return response.status(400).send({message: "Access Denied"});
            }
    }
}

export function get_resources_conf
(
    tenant_model: MongoModel,
    secret: string,
    resources_config: any
)
{
    return async function(request: any, response: any) {
        let token = request.headers['access-token'];
            var host = await tenant_model.model.findOne({tenantname: "host"});
            if(!token) {
                return response.status(400).send({message: "Missing access token"});
            }
            try {
                let decoded = verify(token, secret || "") as SessDecoded;
                if(decoded.permissions.includes("__read__resources_config in host")) {
                    let resources: Array<any> = resources_config.tenant_resources;
                    if(decoded.tenant == host._id) {
                        resources = resources.concat(resources_config.host_resources);
                    }
                    return response.status(200).send({
                        message: `This is resources configuration to render in frontend`,
                        resources: resources
                    });
                } else {
                    return response.status(400).send({message: "Access Denied"});
                }
            } catch(err) {
                return response.status(400).send({message: "Access Denied"});
            }
    }
}

export function get_send_verf_code
(
    plan_manager: PlanManager
)
{
    return async function(request: any, response: any) {
        let err = await plan_manager.send_verf_code(
            request.body.username,
            request.body.email,
            request.body.password,
            request.body.tenantname
        )
        if(!err) {
            return response.status(200).send({
                message: `A verification code was sent to ${request.body.email}`
            });
        } else {
            response.status(400).send({message: "Something bad happened", error: err});
        }
    }
}

export function get_create_tenant_and_admin
(
    plan_manager: PlanManager
)
{
    return async function(request: any, response: any) {
        let ok = await plan_manager.create_tenant_and_admin(
            request.body.username,
            request.body.email,
            request.body.password,
            request.body.tenantname,
            request.body.verfcode
        )
        if(ok) {
            return response.status(200).send({
                message: "Tenant and user created"
            });
        } else {
            response.status(400).send({message: "Bad credentials"});
        }
    }
}
