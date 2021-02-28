import { MongoModel } from 'rest-mongoose';
import { hashSync } from 'bcryptjs';

export async function create_initial_data(
    tstatus_mod: MongoModel,
    tenant_mod: MongoModel,
    permission_mod: MongoModel,
    role_mod: MongoModel,
    ustat_mod: MongoModel,
    user_mod: MongoModel,
    admin_username: string,
    admin_email: string,
    admin_pw: string
)
{
    let current_tstatus = await tstatus_mod.model.find();
    let current_tenant = await tenant_mod.model.find();
    let current_perm = await permission_mod.model.find();
    let current_role = await role_mod.model.find();
    let current_ustatus = await ustat_mod.model.find();
    let current_user = await user_mod.model.find();

    let keys = {
        tstatus: current_tstatus.map( (val: any) => { return val.title; }),
        tenant: current_tenant.map( (val: any)  => { return val.tenantname; }),
        perm: current_perm.map( (val: any)  => { return `${val.title}${val.tenant}`; }),
        role: current_role.map( (val: any)  => { return `${val.title}${val.tenant}`; }),
        ustatus: current_ustatus.map( (val: any)  => { return `${val.title}${val.tenant}`; }),
        user: current_user.map( (val: any)  => { return `${val.username}${val.tenant}`; })
    }

    // ********* Tenant Statuses ***********
    let new_tstatus = [
        {
            title: "__active"
        },
        {
            title: "__inactive"
        },
        {
            title: "__admin"
        },
        {
            title: "__free_plan"
        },
        {
            title: "__pro_plan"
        }
    ]
    .filter( (val: any) => {
        return !keys.tstatus.includes(val.title);
    });

    await tstatus_mod.model.create(new_tstatus);
    let active_tstatus = await tstatus_mod.model.findOne({title: "__active"});
    let admin_tstatus = await tstatus_mod.model.findOne({title: "__admin"});
    active_tstatus = active_tstatus._id;
    admin_tstatus = admin_tstatus._id;

    // ********* Tenants ***********
    let new_tenants = [
        {
            tenantname: "host",
            status: [active_tstatus, admin_tstatus]
        }
    ]
    .filter( (val: any) => {
        return !keys.tenant.includes(val.tenantname);
    });

    await tenant_mod.model.create(new_tenants);
    let host_tenant = await tenant_mod.model.findOne({tenantname: "host"});
    host_tenant = host_tenant._id;

    // ********* Permissions ***********
    let host_admin_perms = [
        {
            title: "__read__tenant_stat",
            tenant: host_tenant
        },
        {
            title: "__write__tenant_stat",
            tenant: host_tenant
        },
        {
            title: "__read__tenant",
            tenant: host_tenant
        },
        {
            title: "__write__tenant",
            tenant: host_tenant
        }
    ]
    let tenant_admin_perms = [
        {
            title: "__read__permission",
            tenant: host_tenant
        },
        {
            title: "__write__permission",
            tenant: host_tenant
        },
        {
            title: "__read__role",
            tenant: host_tenant
        },
        {
            title: "__write__role",
            tenant: host_tenant
        },
        {
            title: "__read__user_stat",
            tenant: host_tenant
        },
        {
            title: "__write__user_stat",
            tenant: host_tenant
        },
        {
            title: "__read__user",
            tenant: host_tenant
        },
        {
            title: "__write__user",
            tenant: host_tenant
        },
        {
            title: "__read__resources_config",
            tenant: host_tenant
        }
    ];

    let new_perms = host_admin_perms.concat(tenant_admin_perms)
    .filter( (val: any) => {
        return !keys.perm.includes(`${val.title}${val.tenant}`);
    });

    await permission_mod.model.create(new_perms);

    let all_perms = await permission_mod.model.find();

    let host_admin_perm_ids = all_perms
    .filter( (val: any) => {
        return host_admin_perms.map( (val1: any) => {
            return `${val1.title}${val1.tenant}`;
        }).includes(`${val.title}${val.tenant}`);
    })
    .map( (val: any) => {
        return val._id;
    });

    let tenant_admin_perm_ids = all_perms
    .filter( (val: any) => {
        return tenant_admin_perms.map( (val1: any) => {
            return `${val1.title}${val1.tenant}`;
        }).includes(`${val.title}${val.tenant}`);
    })
    .map( (val: any) => {
        return val._id;
    });

    // ********* Roles ***********
    let base_roles = [
        {
            title: "__identity_admin",
            permissions : host_admin_perm_ids.concat(tenant_admin_perm_ids),
            tenant: host_tenant
        },
        {
            title: "__tenant_admin",
            permissions : tenant_admin_perm_ids,
            tenant: host_tenant
        }
    ]
    .filter( (val: any) => {
        return !keys.role.includes(`${val.title}${val.tenant}`);
    });

    await role_mod.model.create(base_roles);

    let identity_admin_role = await role_mod.model.findOne({title: "__identity_admin", tenant: host_tenant});
    let tenant_admin_role = await role_mod.model.findOne({title: "__tenant_admin", tenant: host_tenant});

    identity_admin_role = identity_admin_role._id;
    tenant_admin_role = tenant_admin_role._id;

    // ********* User Statuses ***********
    let new_ustatus = [
        {
            title: "__active",
            tenant: host_tenant
        },
        {
            title: "__inactive",
            tenant: host_tenant
        }
    ]
    .filter( (val: any) => {
        return !keys.ustatus.includes(`${val.title}${val.tenant}`);
    });

    await ustat_mod.model.create(new_ustatus);
    let active_ustatus = await ustat_mod.model.findOne({title: "__active"});
    active_ustatus = active_ustatus._id;

    // ********* Users ***********
    let new_users = [
        {
            username: admin_username,
            email : admin_email,
            password: hashSync(admin_pw, 10),
            roles: [identity_admin_role],
            status: [active_ustatus],
            tenant: host_tenant
        }
    ]
    .filter( (val: any) => {
        return !keys.user.includes(`${val.username}${val.tenant}`);
    });

    await user_mod.model.create(new_users);
}