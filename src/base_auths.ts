import { Auth } from 'rest-mongoose';
import { MongoModel } from 'rest-mongoose';

import { verify } from 'jsonwebtoken';

export interface SessDecoded {
    duration: string,
    uid: string,
    username: string,
    useremail: string,
    permissions: Array<string>,
    ustatus: Array<string>,
    tenant: string,
    tstatus: Array<string>,
    roles: string,
    exp: number,
    iat: number
}

export interface TenantLimits {
    admin: {
        permissions: Number,
        roles: Number,
        ustatus: Number,
        users: Number
    },
    free_plan: {
        permissions: Number,
        roles: Number,
        ustatus: Number,
        users: Number
    },
    pro_plan: {
        permissions: Number,
        roles: Number,
        ustatus: Number,
        users: Number
    }
}

export function get_tstatus_auth(model: MongoModel, secret: string, free_actions?: Array<string>) {
    return new Auth(
        model,
        async function(token: string, body: any, action: string, instance_id: string) {
            try {
                var decoded = verify(token, secret || "") as SessDecoded;
                switch(action) {
                    case "FINDALL": case "FINDONE":
                        return decoded.permissions.includes("__read__tenant_stat in host");
                        break;
                    case "CREATE": case "UPDATE": case "DELETE":
                        return decoded.permissions.includes("__write__tenant_stat in host");
                        break;
                }
            } catch(err) {
                return false;
            }
        },
        free_actions || []
    );
}

export function get_tenant_auth(model: MongoModel, secret: string, free_actions?: Array<string>) {
    return new Auth(
        model,
        async function(token: string, body: any, action: string, instance_id: string) {
            try {
                var decoded = verify(token, secret || "") as SessDecoded;
                switch(action) {
                    case "FINDALL": case "FINDONE":
                        return decoded.permissions.includes("__read__tenant in host");
                        break;
                    case "CREATE": case "UPDATE": case "DELETE":
                        return decoded.permissions.includes("__write__tenant in host");
                        break;
                }
            } catch(err) {
                return false;
            }
        },
        free_actions || []
    );
}

export function get_permission_auth(model: MongoModel, tenant_model: MongoModel, secret: string, limits: TenantLimits, free_actions?: Array<string>) {
    return new Auth(
        model,
        async (token: string, body: any, action: string, instance_id: string) => {
            try {
                var decoded = verify(token, secret || "") as SessDecoded;
                var instance = await model.model.findById(instance_id);
                var host = await tenant_model.model.findOne({tenantname: "host"});

                var has_read_perm = decoded.permissions.includes("__read__permission in host");
                var has_write_perm = decoded.permissions.includes("__write__permission in host");

                var tenant_instances = await model.model.find({tenant: decoded.tenant});
                var got_limit: boolean;
                if(decoded.tstatus.includes("__active")) {
                    if(decoded.tstatus.includes("__admin")) {
                        got_limit = tenant_instances.length >= limits.admin.permissions;
                    } else if(decoded.tstatus.includes("__pro_plan")) {
                        got_limit = tenant_instances.length >= limits.pro_plan.permissions;
                    } else if(decoded.tstatus.includes("__free_plan")) {
                        got_limit = tenant_instances.length >= limits.free_plan.permissions;
                    } else {
                        got_limit = true;
                    }
                } else {
                    got_limit = true;
                }

                switch(action) {
                    case "FINDALL":
                        return has_read_perm;
                        break;
                    case "FINDONE":
                        return has_read_perm && (decoded.tenant == host._id || decoded.tenant == instance.tenant);
                        break;
                    case "CREATE":
                        return has_write_perm && !got_limit && (decoded.tenant == host._id || decoded.tenant == body.tenant);
                    case "UPDATE": case "DELETE":
                        return (
                            has_write_perm &&
                            (
                                decoded.tenant == host._id ||
                                (
                                    decoded.tenant == instance.tenant &&
                                    (!body.tenant || body.tenant == decoded.tenant)
                                )
                            )
                        );
                        break;
                }
            } catch(err) {
                return false;
            }
        },
        free_actions || []
    );
}

export function get_role_auth(model: MongoModel, tenant_model: MongoModel, perm_model: MongoModel, secret: string, limits: TenantLimits, free_actions?: Array<string>) {
    return new Auth(
        model,
        async (token: string, body: any, action: string, instance_id: string) => {
            try {
                var decoded = verify(token, secret || "") as SessDecoded;
                var instance = await model.model.findById(instance_id);
                var host = await tenant_model.model.findOne({tenantname: "host"});

                var has_read_perm = decoded.permissions.includes("__read__role in host");
                var has_write_perm = decoded.permissions.includes("__write__role in host");

                var perms_ok = true;
                if(body.permissions) {
                    for(let p of body.permissions) {
                        let perm_instance = await perm_model.model.findById(p);
                        if(perm_instance.tenant != decoded.tenant) {
                            perms_ok = false;
                            break;
                        }
                    }
                }

                var tenant_instances = await model.model.find({tenant: decoded.tenant});
                var got_limit: boolean;
                if(decoded.tstatus.includes("__active")) {
                    if(decoded.tstatus.includes("__admin")) {
                        got_limit = tenant_instances.length >= limits.admin.roles;
                    } else if(decoded.tstatus.includes("__pro_plan")) {
                        got_limit = tenant_instances.length >= limits.pro_plan.roles;
                    } else if(decoded.tstatus.includes("__free_plan")) {
                        got_limit = tenant_instances.length >= limits.free_plan.roles;
                    } else {
                        got_limit = true;
                    }
                } else {
                    got_limit = true;
                }

                switch(action) {
                    case "FINDALL":
                        return has_read_perm;
                        break;
                    case "FINDONE":
                        return has_read_perm && (decoded.tenant == host._id || decoded.tenant == instance.tenant);
                        break;
                    case "CREATE":
                        return (
                            has_write_perm &&
                            !got_limit &&
                            (
                                decoded.tenant == host._id ||
                                (
                                    decoded.tenant == body.tenant &&
                                    perms_ok
                                )
                            ) 
                        );
                    case "UPDATE": case "DELETE":
                        return (
                            has_write_perm &&
                            (
                                decoded.tenant == host._id ||
                                (
                                    decoded.tenant == instance.tenant &&
                                    (!body.tenant || body.tenant == decoded.tenant) &&
                                    perms_ok
                                )
                            )
                        );
                        break;
                }
            } catch(err) {
                return false;
            }
        },
        free_actions || []
    );
}

export function get_ustatus_auth(model: MongoModel, tenant_model: MongoModel, secret: string, limits: TenantLimits, free_actions?: Array<string>) {
    return new Auth(
        model,
        async (token: string, body: any, action: string, instance_id: string) => {
            try {
                var decoded = verify(token, secret || "") as SessDecoded;
                var instance = await model.model.findById(instance_id);
                var host = await tenant_model.model.findOne({tenantname: "host"});

                var has_read_perm = decoded.permissions.includes("__read__user_stat in host");
                var has_write_perm = decoded.permissions.includes("__write__user_stat in host");

                var tenant_instances = await model.model.find({tenant: decoded.tenant});
                var got_limit: boolean;
                if(decoded.tstatus.includes("__active")) {
                    if(decoded.tstatus.includes("__admin")) {
                        got_limit = tenant_instances.length >= limits.admin.ustatus;
                    } else if(decoded.tstatus.includes("__pro_plan")) {
                        got_limit = tenant_instances.length >= limits.pro_plan.ustatus;
                    } else if(decoded.tstatus.includes("__free_plan")) {
                        got_limit = tenant_instances.length >= limits.free_plan.ustatus;
                    } else {
                        got_limit = true;
                    }
                } else {
                    got_limit = true;
                }

                switch(action) {
                    case "FINDALL":
                        return has_read_perm;
                        break;
                    case "FINDONE":
                        return has_read_perm && (decoded.tenant == host._id || decoded.tenant == instance.tenant);
                        break;
                    case "CREATE":
                        return has_write_perm && !got_limit && (decoded.tenant == host._id || decoded.tenant == body.tenant);
                    case "UPDATE": case "DELETE":
                        return (
                            has_write_perm &&
                            (
                                decoded.tenant == host._id ||
                                (
                                    decoded.tenant == instance.tenant &&
                                    (!body.tenant || body.tenant == decoded.tenant)
                                )
                            ) 
                        );
                        break;
                }
            } catch(err) {
                return false;
            }
        },
        free_actions || []
    );
}

export function get_user_auth(model: MongoModel, tenant_model: MongoModel, role_model: MongoModel, ustatus_model: MongoModel, secret: string, limits: TenantLimits, free_actions?: Array<string>) {
    return new Auth(
        model,
        async (token: string, body: any, action: string, instance_id: string) => {
            try {
                var decoded = verify(token, secret || "") as SessDecoded;
                var instance = await model.model.findById(instance_id);
                var host = await tenant_model.model.findOne({tenantname: "host"});

                var has_read_perm = decoded.permissions.includes("__read__user in host");
                var has_write_perm = decoded.permissions.includes("__write__user in host");

                var roles_ok = true;
                var status_ok = true;
                if(body.roles) {
                    for(let r of body.roles) {
                        let role_instance = await role_model.model.findById(r);
                        if(role_instance.tenant != decoded.tenant) {
                            roles_ok = false;
                            break;
                        }
                    }
                }
                if(body.status) {
                    for(let s of body.status) {
                        let status_instance = await ustatus_model.model.findById(s);
                        if(status_instance.tenant != decoded.tenant) {
                            status_ok = false;
                            break;
                        }
                    }
                }

                var tenant_instances = await model.model.find({tenant: decoded.tenant});
                var got_limit: boolean;
                if(decoded.tstatus.includes("__active")) {
                    if(decoded.tstatus.includes("__admin")) {
                        got_limit = tenant_instances.length >= limits.admin.users;
                    } else if(decoded.tstatus.includes("__pro_plan")) {
                        got_limit = tenant_instances.length >= limits.pro_plan.users;
                    } else if(decoded.tstatus.includes("__free_plan")) {
                        got_limit = tenant_instances.length >= limits.free_plan.users;
                    } else {
                        got_limit = true;
                    }
                } else {
                    got_limit = true;
                }

                switch(action) {
                    case "FINDALL":
                        return has_read_perm;
                        break;
                    case "FINDONE":
                        return has_read_perm && (decoded.tenant == host._id || decoded.tenant == instance.tenant);
                        break;
                    case "CREATE":
                        return (
                            has_write_perm &&
                            !got_limit &&
                            (
                                decoded.tenant == host._id ||
                                (
                                    decoded.tenant == body.tenant &&
                                    roles_ok &&
                                    status_ok
                                )
                            )
                        );
                    case "UPDATE": case "DELETE":
                        return (
                            has_write_perm &&
                            (
                                decoded.tenant == host._id ||
                                (
                                    decoded.tenant == instance.tenant &&
                                    (!body.tenant || body.tenant == decoded.tenant) &&
                                    roles_ok &&
                                    status_ok
                                )
                            )
                        )
                        break;
                }
            } catch(err) {
                return false;
            }
        },
        free_actions || []
    );
}