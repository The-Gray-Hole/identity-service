import { MongoModel } from 'rest-mongoose';
import { verify } from 'jsonwebtoken';

import { SessDecoded } from './base_auths';

export function get_tstatus_callback() {
    return async function(action: string, request: any, data: any) {}
}

export function get_tenant_callback() {
    return async function(action: string, request: any, data: any) {}
}

export function get_perm_callback(tenant_model: MongoModel, secret: string) {
    return async function(action: string, request: any, data: any) {
        try{
            if(action != "FINDALL") return data;

            var host = await tenant_model.model.findOne({tenantname: "host"});
            let token = request.headers["access-token"];
            var decoded = verify(token, secret || "") as SessDecoded;

            if(decoded.tenant == host._id) return data;

            let instances = data as Array<any>;
            instances = instances.filter( (val: any) => {
                return val.tenant == decoded.tenant;
            });
            return instances;
        } catch {
            return null;
        }
    }
}

export function get_role_callback(tenant_model: MongoModel, secret: string) {
    return async function(action: string, request: any, data: any) {
        try{
            if(action != "FINDALL") return data;

            var host = await tenant_model.model.findOne({tenantname: "host"});
            let token = request.headers["access-token"];
            var decoded = verify(token, secret || "") as SessDecoded;

            if(decoded.tenant == host._id) return data;

            let instances = data as Array<any>;
            instances = instances.filter( (val: any) => {
                return val.tenant == decoded.tenant;
            });
            return instances;
        } catch {
            return null;
        }
    }
}

export function get_ustatus_callback(tenant_model: MongoModel, secret: string) {
    return async function(action: string, request: any, data: any) {
        try{
            if(action != "FINDALL") return data;

            var host = await tenant_model.model.findOne({tenantname: "host"});
            let token = request.headers["access-token"];
            var decoded = verify(token, secret || "") as SessDecoded;

            if(decoded.tenant == host._id) return data;

            let instances = data as Array<any>;
            instances = instances.filter( (val: any) => {
                return val.tenant == decoded.tenant;
            });
            return instances;
        } catch {
            return null;
        }
    }
}

export function get_user_callback(tenant_model: MongoModel, secret: string) {
    return async function(action: string, request: any, data: any) {
        try{
            if(action != "FINDALL") return data;

            var host = await tenant_model.model.findOne({tenantname: "host"});
            let token = request.headers["access-token"];
            var decoded = verify(token, secret || "") as SessDecoded;

            if(decoded.tenant == host._id) return data;

            let instances = data as Array<any>;
            instances = instances.filter( (val: any) => {
                return val.tenant == decoded.tenant;
            });
            return instances;
        } catch {
            return null;
        }
    }
}