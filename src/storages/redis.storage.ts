import Redis from 'ioredis';

import Base from '../base';
import { Permission } from '../permission';
import { Role } from '../role';
import { RecordType, RoleType, TypeEnum } from '../types';
import aclLogger from '../util/logger';
import Storage from './index';

aclLogger.mute(false);
const KEY_ROLE = 'RBACRole:';
const KEY_PERMISSION = 'RBACPermission:';

const getRoleKey = (roleName: string) => `${KEY_ROLE}${roleName}`;
const getPermissionKey = (permission: string) => `${KEY_PERMISSION}${permission}`;

export class RedisStorage extends Storage {
  #client: Redis;
  constructor() {
    super();

    this.#client = new Redis({
      host: 'localhost',
      password: '',
      port: 6379,
      maxRetriesPerRequest: null,
      enableReadyCheck: false,
      reconnectOnError: () => true,
    });
  }

  async add(item: Base): Promise<boolean> {
    await this.addToSet(item);

    return true;
  }

  async remove(item: Base): Promise<boolean> {
    const { name } = item;
    const items = await this.getItemsValue(TypeEnum.ROLE);

    for await (const role of items) {
      if (role.grants) {
        role.grants = role.grants?.filter(grant => grant !== item.name);
        await this.setItemValue(role.name, role);
      }
    }

    this.#client.del(getRoleKey(item.name));
    this.#client.del(getPermissionKey(item.name));

    aclLogger.log(`remove ${name} rule and his child`);

    return true;
  }

  async grant(role: Role, child: Base): Promise<boolean> {
    const { name } = role;
    const { name: childName } = child;

    await this.checkByExists(name, childName);

    if (name === childName) {
      throw new Error(`You can grant yourself ${name}`);
    }
    const roleItem = await this.getItemByKey(getRoleKey(name));

    if (!roleItem.grants?.includes(childName)) {
      const value = {
        ...roleItem,
        grants: roleItem.grants?.concat(childName),
      };

      await this.setItemValue(getRoleKey(name), value);
    }

    aclLogger.log(`grant rule '${childName}' to role '${name}'`);

    return true;
  }

  async revoke(role: Role, child: Base): Promise<boolean> {
    const { name } = role;
    const { name: childName } = child;

    await this.checkByExists(name, childName);
    const item = await this.getItemByKey(getRoleKey(name));

    if (!item.grants?.includes(childName)) {
      throw new Error('Rule is not associated to this role');
    }

    await this.setItemValue(getRoleKey(name), {
      ...item,
      grants: item.grants?.filter(grant => grant !== childName),
    });

    aclLogger.log(`revoke rule '${childName}' from role '${name}'`);

    return true;
  }

  async get(name: string): Promise<Base | undefined> {
    try {
      const item = await this.getItemByKey(getRoleKey(name));

      return this.convertToInstance(item);
    } catch {
      /* empty */
    }

    try {
      const item = await this.getItemByKey(getPermissionKey(name));

      return this.convertToInstance(item);
    } catch {
      /* empty */
    }

    return undefined;
  }

  async getRoles(): Promise<Role[]> {
    const items = await this.getItemsValue(TypeEnum.ROLE);
    const roles: Role[] = [];

    if (items.length === 0) {
      return roles;
    }

    for await (const item of items) {
      const role = await this.convertToInstance(item);
      roles.push(role as Role);
    }

    return roles;
  }

  async getPermissions(): Promise<Permission[]> {
    const items = await this.getItemsValue(TypeEnum.PERMISSION);
    const permissions: Permission[] = [];

    if (items.length === 0) {
      return permissions;
    }

    for await (const item of items) {
      const permission = await this.convertToInstance(item);
      permissions.push(permission as Permission);
    }

    return permissions;
  }

  async getGrants(roleName: RoleType): Promise<Base[]> {
    const grants: Base[] = [];

    try {
      const itemRole = await this.getItemByKey(getRoleKey(roleName));
      const currentGrunts = itemRole?.grants;

      if (!currentGrunts || currentGrunts.length > 0) {
        const itemsRole = await this.getItemsValue(TypeEnum.ROLE);

        if (itemsRole.length) {
          for (const role of itemsRole) {
            if (currentGrunts?.includes(role.name)) {
              grants.push(await this.convertToInstance(role));
            }
          }
        }

        const itemsPermission = await this.getItemsValue(TypeEnum.PERMISSION);

        if (itemsPermission.length) {
          for (const permission of itemsPermission) {
            if (currentGrunts?.includes(permission.name)) {
              grants.push(await this.convertToInstance(permission));
            }
          }
        }
      }
    } catch {
      /* empty */
    }

    return grants;
  }

  private async addToSet(item: Base) {
    const type = this.getType(item);

    if (!type) {
      throw new Error('Item has wrong type!');
    }

    if (type === TypeEnum.ROLE) {
      if (await this.existsRoleKey(item.name)) {
        const role = await this.getItemValue(item);
        role.name = item.name;
        await this.setItemValue(getRoleKey(item.name), role);
      } else {
        const value = {
          type: type as TypeEnum,
          name: item.name as RoleType,
          grants: [],
        } as RecordType;

        await this.setItemValue(getRoleKey(item.name), value);
      }

      aclLogger.info(`Role ${item.name} added`);
    } else if (type === TypeEnum.PERMISSION) {
      if (await this.existsPermissionKey(item.name)) {
        const permission = await this.getItemValue(item);
        permission.name = item.name;
        await this.setItemValue(getPermissionKey(item.name), permission);
      } else {
        const value = {
          type: type as TypeEnum,
          name: item.name as RoleType,
        } as RecordType;

        await this.setItemValue(getPermissionKey(item.name), value);
        aclLogger.info(`Permission ${item.name} added`);
      }
    } /* else {
      throw new Error('Type is not implemented to set!');
    }*/
  }

  private async setItemValue(key: string, value: RecordType) {
    return this.#client.set(key, JSON.stringify(value));
  }

  private async getItemValue(item: Base, overwrite?: string) {
    const type = this.getType(item);
    const key = type === TypeEnum.PERMISSION ? getPermissionKey(item.name) : getRoleKey(item.name);

    return this.getItemByKey(overwrite ?? key);
  }

  private async getItemByKey(key: string) {
    const value = await this.#client.get(key);
    if (value) {
      return JSON.parse(value) as RecordType;
    }

    throw new Error(`Empty value of key '${key}'`);
  }

  private async existsRoleKey(roleName: string) {
    return this.#client.exists(getRoleKey(roleName));
  }

  private async existsPermissionKey(permission: string) {
    return this.#client.exists(getPermissionKey(permission));
  }

  private async checkByExists(name: string, childName: string) {
    if (!(await this.existsRoleKey(name))) {
      throw new Error(`Role ${name} is not exist`);
    }

    if (
      (await Promise.all([this.existsRoleKey(childName), this.existsPermissionKey(childName)])).filter(Boolean)
        .length === 0
    ) {
      throw new Error(`Rule ${childName} is not exist`);
    }

    return true;
  }

  private async getItemsValue(type: TypeEnum) {
    const keys = await this.#client.keys(`${type === TypeEnum.PERMISSION ? KEY_PERMISSION : KEY_ROLE}*`);
    const results: RecordType[] = [];

    for await (const key of keys) {
      const item = await this.getItemByKey(key);
      results.push(item);
    }

    return results;
  }
}
