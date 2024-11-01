import { GrantType, RecordType } from 'hrbac';

import Base from '../base';
import { TypeEnum } from '../enums';
import { Permission } from '../permission';
import type { RBAC } from '../rbac';
import { Role } from '../role';

const takeError = (nameMethod: string) => new Error(`Storage method '${nameMethod}' is not implemented`);

export default class Storage<R extends string, A extends string, RS extends string> {
  public rbac: RBAC<R, A, RS> | null = null;

  useRBAC(rbac: RBAC<R, A, RS>): void {
    if (this.rbac) {
      throw new Error('Storage is already in use with another instance of RBAC');
    }

    this.rbac = rbac;
  }

  /** Add permission or role */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async add(item: Base<R, A, RS>): Promise<boolean> {
    throw takeError('add');
  }

  /** Remove permission or role */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async remove(item: Base<R, A, RS>): Promise<boolean> {
    throw takeError('remove');
  }

  /** Add (grant) permission or role to hierarchy of actual role */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async grant(role: Role<R, A, RS>, child: Base<R, A, RS>): Promise<boolean> {
    if (role.name === child.name) {
      throw new Error('You can grant yourself');
    }

    throw takeError('grant');
  }

  /** Remove (revoke) permission or role from hierarchy of actual role */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async revoke(role: Role<R, A, RS>, child: Base<R, A, RS>): Promise<boolean> {
    throw takeError('revoke');
  }

  /** Get instance of permission or role by his name */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async get(name: R | GrantType<A, RS>): Promise<Base<R, A, RS> | undefined> {
    throw takeError('get');
  }

  /** Get all instances of Roles */
  async getRoles(): Promise<Role<R, A, RS>[]> {
    throw takeError('getRoles');
  }

  /** Get all instances of Permissions */
  async getPermissions(): Promise<Permission<R, A, RS>[]> {
    throw takeError('getPermissions');
  }

  /** Get instances of Roles and Permissions assigned to role */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async getGrants(roleName: R): Promise<Base<R, A, RS>[]> {
    throw takeError('getGrants');
  }

  /** Get instance of role by his name */
  async getRole(roleName: R): Promise<Role<R, A, RS> | undefined> {
    const role = await this.get(roleName);
    if (role && role instanceof Role) {
      return role;
    }

    return undefined;
  }

  /** Get instance of permission by his name */
  async getPermission(action: A, resource: RS): Promise<Permission<R, A, RS> | undefined> {
    if (!this.rbac) {
      throw new Error('RBAC instance not set!');
    }

    const name = Permission.createName(action, resource, this.rbac.options.delimiter);
    const item = await this.get(name);

    if (item && item instanceof Permission) {
      return item;
    }

    return undefined;
  }

  /** Return true with callback if role or permission exists */
  async exists(name: R | GrantType<A, RS>): Promise<boolean> {
    const item = await this.get(name);

    return !!item;
  }

  /** Return true with callback if role exists */
  async existsRole(roleName: R): Promise<boolean> {
    const role = await this.getRole(roleName);

    return !!role;
  }

  /** Return true with callback if permission exists */
  async existsPermission(action: A, resource: RS): Promise<boolean> {
    const permission = await this.getPermission(action, resource);

    return !!permission;
  }

  protected getType(item: Base<R, A, RS>): TypeEnum | null {
    if (item instanceof Role) {
      return TypeEnum.ROLE;
    } else if (item instanceof Permission) {
      return TypeEnum.PERMISSION;
    }

    return null;
  }

  protected convertToInstance(record?: RecordType<R, A, RS>): Promise<Role<R, A, RS> | Permission<R, A, RS>> {
    const rbac = this.rbac as RBAC<R, A, RS>;

    if (!record) {
      throw new Error('Record is undefined');
    }

    if (record.type === TypeEnum.ROLE) {
      return rbac.createRole(record.name as R, false);
    } else if (record.type === TypeEnum.PERMISSION) {
      const decoded = Permission.decodeName(record.name as GrantType<A, RS>);

      if (!decoded) {
        throw new Error('Bad permission name');
      }

      return rbac.createPermission(decoded.action as A, decoded.resource as RS, false);
    }

    throw new Error('Type is undefined');
  }
}
