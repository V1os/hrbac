import { RecordType } from 'hrbac';
import { Model, Schema as MongooseSchema } from 'mongoose';
import type { Connection } from 'mongoose';

import Storage from '.';
import Base from '../base';
import { TypeEnum } from '../enums';
import { Permission } from '../permission';
import { Role } from '../role';

type OptionsType<R extends string, A extends string, RS extends string> = {
  connection?: Connection;
  modelName?: string;
  Schema: typeof MongooseSchema<RecordType<R, A, RS>>;
};

function createSchema<R extends string, A extends string, RS extends string>(
  Schema: typeof MongooseSchema<RecordType<R, A, RS>>,
) {
  return new Schema({
    type: { type: String, enum: TypeEnum, required: true },
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    name: { type: String, required: true, unique: true },
    grants: [String],
  });
}

export class MongooseStorage<R extends string, A extends string, RS extends string> extends Storage<R, A, RS> {
  readonly #options: OptionsType<R, A, RS>;
  readonly #model: Model<RecordType<R, A, RS>>;

  constructor(options: OptionsType<R, A, RS>) {
    super();
    const { modelName = 'rbac', Schema = MongooseSchema, connection } = options;

    // const connection = options.connection;
    if (!connection) {
      throw new Error('Parameter connection is undefined use your current mongoose connection.');
    }

    this.#options = options;

    this.#model = connection.model(modelName, createSchema<R, A, RS>(Schema));
  }

  get model() {
    return this.#model;
  }

  get options() {
    return this.#options;
  }

  async add(item: Base<R, A, RS>) {
    const obj = await this.model.create({
      name: item.name,
      type: this.getType(item),
    });

    if (!obj) {
      throw new Error('Item is undefined');
    }

    return true;
  }

  async remove(item: Base<R, A, RS>) {
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

  async grant(role: Base<R, A, RS>, child: Base<R, A, RS>) {
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

  async revoke(role: Base<R, A, RS>, child: Base<R, A, RS>) {
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

  async get(name: string): Promise<Base<R, A, RS> | undefined> {
    const record = await this.model.findOne({ name });

    if (record) {
      return this.convertToInstance(record);
    } else {
      return undefined;
    }
  }

  async getRoles(): Promise<Role<R, A, RS>[]> {
    const records = await this.model.find({ type: TypeEnum.ROLE });

    return records.map(r => this.convertToInstance(r) as unknown as Role<R, A, RS>);
  }

  async getPermissions(): Promise<Permission<R, A, RS>[]> {
    const records = await this.model.find({ type: TypeEnum.PERMISSION });

    return records.map(r => this.convertToInstance(r) as unknown as Permission<R, A, RS>);
  }

  async getGrants(role: R): Promise<Base<R, A, RS>[]> {
    const record = await this.model.findOne({ name: role, type: TypeEnum.ROLE });

    if (!record || !record.grants?.length) {
      return [];
    }

    const records = await this.model.find({ name: record.grants });

    return records.map(r => this.convertToInstance(r) as unknown as Base<R, A, RS>);
  }
}
