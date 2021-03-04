import { MongoModel } from "rest-mongoose";
import { sign } from 'jsonwebtoken';
import { hashSync } from 'bcryptjs';

import { createTransport } from 'nodemailer';

export class PlanManager {
    private _tenant_model: MongoModel;
    private _tstatus_model: MongoModel;
    private _role_model: MongoModel;
    private _ustatus_model: MongoModel;
    private _user_model: MongoModel;
    private _secret: string;
    private _root_email: string;
    private _root_epassword: any;
    private _valid_codes: Set<string>;

    constructor
    (
        tenant_model: MongoModel,
        tstatus_model: MongoModel,
        role_model: MongoModel,
        ustatus_model: MongoModel,
        user_model: MongoModel,
        secret: string,
        root_email: string,
        root_epassword: string
    )
    {
        this._tenant_model = tenant_model;
        this._user_model = user_model;
        this._tstatus_model = tstatus_model;
        this._role_model = role_model;
        this._ustatus_model = ustatus_model;
        this._secret = secret;
        this._root_email = root_email;
        this._valid_codes = new Set();
        this._root_epassword = root_epassword;
    }

    async send_verf_code(username: string, email: string, password: string, tenant_name: string) {
        let num1 = this.encode_word(sign(username, this._secret));
        let num2 = this.encode_word(sign(email, this._secret));
        let num3 = this.encode_word(sign(password, this._secret));
        let num4 = this.encode_word(sign(tenant_name, this._secret));

        return new Promise(( resolve: any, reject: any) => {
            var transporter = createTransport({
                service: 'gmail',
                auth: {
                  user: this._root_email,
                  pass: this._root_epassword
                }
            });
            var mailOptions = {
                from: `"The Gray Hole Team" <${this._root_email}>`,
                to: email,
                subject: 'New User verfification code',
                text: `The Gray Hole Verification Code: ${num1}${num2}${num3}${num4}`
            };
            transporter.sendMail(mailOptions, (error: any, info: any) => {
                if(error) {
                    resolve(error);
                } else {
                    resolve(null);
                }
            });
        });
    }

    async create_tenant_and_admin
    (
        username: string,
        email: string,
        password: string,
        tenant_name: string,
        verf_code: string
    )
    {
        let num1 = this.encode_word(sign(username, this._secret));
        let num2 = this.encode_word(sign(email, this._secret));
        let num3 = this.encode_word(sign(password, this._secret));
        let num4 = this.encode_word(sign(tenant_name, this._secret));
        let code = `${num1}${num2}${num3}${num4}`
        if(code == verf_code && this._valid_codes.has(code)) {
            try {
                let host_tenant = await this._tenant_model.model.findOne({tenantname: "host"});
                host_tenant = host_tenant._id;

                let tenant_active = await this._tstatus_model.model.findOne({title: "__active"});
                let free_plan = await this._tstatus_model.model.findOne({title: "__free_plan"});
                let tenant_admin_role = await this._role_model.model.findOne({title: "__tenant_admin", tenant: host_tenant});
                let active_ustatus = await this._ustatus_model.model.findOne({title: "__active", tenant: host_tenant});

                tenant_active = tenant_active._id;
                free_plan = free_plan._id;
                tenant_admin_role = tenant_admin_role._id;
                active_ustatus = active_ustatus._id;

                let current_tenants = await this._tenant_model.model.find();
                let keys = {
                    tenant: current_tenants.map( (val: any)  => { return val.tenantname; })
                }
                if(keys.tenant.includes(tenant_name)) {
                    return false;
                }

                let new_tenant = [
                    {
                        tenantname: tenant_name,
                        status: [tenant_active, free_plan],
                        plan_exp: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30)
                    }
                ]
                await this._tenant_model.model.create(new_tenant);
                let the_new_tenant = await this._tenant_model.model.findOne({tenantname: tenant_name});
                the_new_tenant = the_new_tenant._id;

                let new_user = [
                    {
                        username: username,
                        email : email,
                        password: hashSync(password, 10),
                        roles: [tenant_admin_role],
                        status: [active_ustatus],
                        tenant: the_new_tenant
                    }
                ]
                await this._user_model.model.create(new_user);
                return true;
            } catch {
                return false;
            }
        } else {
            return false;
        }
    }

    encode_word(word: string) {
        let sum = 0;
        for(let c = 0; c < word.length; c++) {
            sum += word.charCodeAt(c);
        }
        let code = sum % 90 + 10;
        return code.toString();
    }

}


