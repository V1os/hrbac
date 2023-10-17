import { Model, Schema as MongooseSchema } from 'mongoose';
import type { Connection } from 'mongoose';

import Storage from '.';
import Base from '../base';
import { Permission } from '../permission';
import { Role } from '../role';
import { RoleType, TypeEnum, RecordType } from '../types';

type OptionsType = {
  connection?: Connection;
  modelName?: string;
  Schema: typeof MongooseSchema<RecordType>;
};

function createSchema(Schema: typeof MongooseSchema<RecordType>) {
  return new Schema({
    name: { type: String, required: true, unique: true },
    type: { type: String, enum: ['PERMISSION', 'ROLE'], required: true },
    grants: [String],
  });
}

export class MongooseStorage extends Storage {
  readonly #options: OptionsType;
  readonly #model: Model<RecordType>;

  constructor(options: OptionsType) {
    super();
    const { modelName = 'rbac', Schema = MongooseSchema, connection } = options;

    // const connection = options.connection;
    if (!connection) {
      throw new Error('Parameter connection is undefined use your current mongoose connection.');
    }

    this.#options = options;

    this.#model = connection.model(modelName, createSchema(Schema));
  }

  get model() {
    return this.#model;
  }

  get options() {
    return this.#options;
  }

  async add(item: Base) {
    const obj = await this.model.create({
      name: item.name,
      type: this.getType(item),
    });

    if (!obj) {
      throw new Error('Item is undefined');
    }

    return true;
  }

  async remove(item: Base) {
    const name = item.name;

    const { acknowledged, matchedCount } = await this.model.updateMany(
      { grants: name },
      {
        $pull: {
          grants: name,
        },
      },
      { multi: true },
    );

    if (acknowledged && matchedCount) {
      await this.model.deleteOne({ name });
    }

    return true;
  }

  async grant(role: Base, child: Base) {
    const name = role.name;
    const childName = child.name;

    // if (!role instanceof Role) {
    //   throw new Error('Role is not instance of Role');
    // }

    if (name === childName) {
      throw new Error('You can grant yourself');
    }

    await this.model.updateOne({ name, type: TypeEnum.ROLE }, { $addToSet: { grants: childName } });

    return true;
  }

  async revoke(role: Base, child: Base) {
    const name = role.name;
    const childName = child.name;

    const { matchedCount } = await this.model.updateOne(
      { name, type: TypeEnum.ROLE },
      { $pull: { grants: childName } },
    );

    if (matchedCount === 0) {
      throw new Error('Item is not associated to this item');
    }

    return true;
  }

  async get(name: string) {
    const record = await this.model.findOne({ name });

    if (record) {
      return this.convertToInstance(record);
    } else {
      return undefined;
    }
  }

  async getRoles(): Promise<Role[]> {
    const records = await this.model.find({ type: TypeEnum.ROLE });

    return records.map(r => this.convertToInstance(r) as unknown as Role);
  }

  async getPermissions(): Promise<Permission[]> {
    const records = await this.model.find({ type: TypeEnum.PERMISSION });

    return records.map(r => this.convertToInstance(r) as unknown as Permission);
  }

  async getGrants(role: RoleType): Promise<Base[]> {
    const record = await this.model.findOne({ name: role, type: TypeEnum.ROLE });

    if (!record || !record.grants.length) {
      return [];
    }

    const records = await this.model.find({ name: record.grants });

    return records.map(r => this.convertToInstance(r) as unknown as Base);
  }
}
