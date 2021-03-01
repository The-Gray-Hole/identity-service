import { MongoModel } from "rest-mongoose";

export class PlanManager {
    private _tenant_model: MongoModel;

    constructor(tenant_model: MongoModel) {
        this._tenant_model = tenant_model;
    }
}