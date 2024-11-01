import { GrantType } from 'hrbac';

import Base from '../base';
import { Permission } from '../permission';
import { Role } from '../role';
import aclLogger from '../utils/logger';
import Storage from './index';

type ItemType<R extends string, A extends string, RS extends string> = {
  instance: Base<R, A, RS>;
  grants: (GrantType<A, RS> | R)[];
};

aclLogger.mute(false);

export class MemoryStorage<R extends string, A extends string, RS extends string> extends Storage<R, A, RS> {
  items: Record<string, ItemType<R, A, RS>> = {};

  async add(item: Base<R, A, RS>): Promise<boolean> {
    const { name } = item;
    if (this.items[name]) {
      throw new Error(`Item ${name} already exists`);
    }

    this.items[name] = {
      instance: item,
      grants: [],
    };

    aclLogger.log(`add ${this.getType(item)} ${item.name}`);

    return true;
  }

  async remove(item: Base<R, A, RS>): Promise<boolean> {
    const { items } = this;
    const { name } = item;
    if (!items[name]) {
      throw new Error(`Item ${name} is not presented in storage`);
    }

    // revoke from all instances
    Object.keys(items).forEach((itemName: string) => {
      const { grants } = items[itemName];
      items[itemName].grants = grants.filter(grant => grant !== name);
    });

    // delete from items
    delete this.items[name];

    aclLogger.log(`remove ${name} rule and his child`);

    return true;
  }

  async grant(role: Role<R, A, RS>, child: Base<R, A, RS>): Promise<boolean> {
    const { name } = role;
    const { name: childName } = child;

    if (!this.items[name]) {
      throw new Error(`Role ${name} is not exist`);
    }

    if (!this.items[childName]) {
      throw new Error(`Base ${childName} is not exist`);
    }

    if (name === childName) {
      throw new Error(`You can grant yourself ${name}`);
    }

    const { grants } = this.items[name];
    if (!grants.includes(childName)) {
      grants.push(childName);
    }

    aclLogger.log(`grant ${childName} to ${name}`);

    return true;
  }

  async revoke(role: Role<R, A, RS>, child: Base<R, A, RS>): Promise<boolean> {
    const { name } = role;
    const { name: childName } = child;

    if (!this.items[name] || !this.items[childName]) {
      throw new Error('Role is not exist');
    }

    const { grants } = this.items[name];
    if (!grants.includes(childName)) {
      throw new Error('Item is not associated to this item');
    }

    this.items[name].grants = grants.filter(grant => grant !== childName);

    aclLogger.log(`revoke ${childName} from ${name}`);

    return true;
  }

  async get(name: string): Promise<Base<R, A, RS> | undefined> {
    if (name && this.items[name]) {
      return this.items[name].instance;
    }

    return undefined;
  }

  async getRoles(): Promise<Role<R, A, RS>[]> {
    return Object.values(this.items).reduce((filtered: Role<R, A, RS>[], item: ItemType<R, A, RS>) => {
      const { instance } = item;

      if (instance instanceof Role) {
        filtered.push(instance);
      }

      return filtered;
    }, []);
  }

  async getPermissions(): Promise<Permission<R, A, RS>[]> {
    return Object.values(this.items).reduce((filtered: Permission<R, A, RS>[], item: ItemType<R, A, RS>) => {
      const { instance } = item;

      if (instance instanceof Permission) {
        filtered.push(instance);
      }

      return filtered;
    }, []);
  }

  async getGrants(role: string): Promise<Base<R, A, RS>[]> {
    if (role && this.items[role]) {
      const currentGrants = this.items[role].grants;

      return currentGrants.reduce((filtered: Base<R, A, RS>[], grantName: string) => {
        const grant = this.items[grantName];
        if (grant) {
          filtered.push(grant.instance);
        }

        return filtered;
      }, []);
    }

    return [];
  }
}
