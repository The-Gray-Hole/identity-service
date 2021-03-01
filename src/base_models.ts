import { MongoModel } from 'rest-mongoose';
import { Types } from 'mongoose';

var validateEmail = function(email: string) {
    var re = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    return re.test(email)
};

export function get_tstatus_model() {
    return new MongoModel(
        "tstatus",
        {
            title: {
                type: String,
                unique: true,
                required: true
            }
        },
        true
    );
}

export function get_tenant_model() {
    return new MongoModel(
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
            }],
            plan_exp: {
                type: Date,
                unique: false,
                required: false
            }
        },
        true
    );
}

export function get_permission_model() {
    return new MongoModel(
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
}

export function get_role_model() {
    return new MongoModel(
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
}

export function get_ustatus_model() {
    return new MongoModel(
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
    );
}

export function get_user_model() {
    return new MongoModel(
        "user",
        {
            username: {
                type: String,
                required: true
            },
            email: {
                type: String,
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
}