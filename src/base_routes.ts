import { MongoModel } from 'rest-mongoose';
import { compareSync } from 'bcryptjs';
import { sign } from 'jsonwebtoken';
import { verify } from 'jsonwebtoken';

import { SessDecoded } from './base_auths';

import resources_config from './resources_config.json';

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
                        "/tstatuss:tstatusid",
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
                        "/check_permission",
                        "/get_uid"
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
            for(let i = 0; i < user.roles.length; i++) {
                let role = await role_model.model.findById(user.roles[i]);
                for(let j = 0; j < role.permissions.length; j++) {
                    let p = await perm_model.model.findById(role.permissions[j]);
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
                permissions: perms,
                tenant: user.tenant,
            }, secret)

            response.status(200).send({
                session_token: _session_token
            });
        } catch {
            return response.status(400).send({message: "Invalid credentials"});
        }
    }
}

export function get_check_perm
(
    secret: string
)
{
    return async function(request: any, response: any) {
        let token = request.headers['access-token'];
            let permission = request.body.permission;
            let tenant = request.body.tenant;
            if(!token) {
                return response.status(400).send({message: "Missing access token"});
            }
            try {
                let decoded = verify(token, secret || "") as SessDecoded;
                if(decoded.permissions.includes(permission) && decoded.tenant == tenant) {
                    return response.status(200).send({
                        message: `The user ${decoded.username} has permission to ${permission} for tenant ${tenant}`,
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
    }
}

export function get_get_uid
(
    secret: string
)
{
    return async function(request: any, response: any) {
        let token = request.headers['access-token'];
            if(!token) {
                return response.status(400).send({message: "Missing access token"});
            }
            try {
                let decoded = verify(token, secret || "") as SessDecoded;
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
    }
}

export function get_resources_conf
(
    tenant_model: MongoModel,
    secret: string
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
                if(decoded.permissions.includes("__read__resources_config")) {
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
