import {
  RBACOptionsType,
  PermissionParam,
  GrantType,
  TraverseGrantsParams,
  RBACType,
  GrantsType,
  PermissionType,
} from 'hrbac';
import isPlainObject from 'lodash/isPlainObject';

import Base from './base';
import { GRAND_DELIMITER, RBAC_DEFAULT_OPTIONS } from './config/default';
import { Permission } from './permission';
import { Role } from './role';
import Storage from './storages';
import { MemoryStorage } from './storages/memory.storage';
import logger from './utils/logger';

logger.mute(false);

export class RBAC<R extends string, A extends string, RS extends string> {
  public options: RBACOptionsType<R, A, RS>;
  private storage: Storage<R, A, RS>;

  #upRule = false;

  static Role: typeof Role;
  static Permission: typeof Permission;
  static Storage: typeof Storage;

  /** Convert Array of permissions to permission name */
  static getPermissionNames<A extends string, R extends string>(
    permissions: PermissionParam<A, R>[],
    delimiter: string = GRAND_DELIMITER,
  ): string[] {
    if (!delimiter) {
      throw new Error('Delimiter is not defined');
    }

    return permissions.map(([action, resource]) => Permission.createName(action, resource, delimiter));
  }

  constructor(options?: Partial<RBACOptionsType<R, A, RS>>) {
    this.options = {
      ...RBAC_DEFAULT_OPTIONS,
      ...options,
    };

    this.storage = <Storage<R, A, RS>>this.options.storage || new MemoryStorage<R, A, RS>();
    this.storage.useRBAC(this);
  }

  protected set upRule(value: boolean) {
    this.#upRule = value;
  }

  get upRule() {
    return this.#upRule;
  }

  async init(force: boolean = true) {
    const { roles, permissions, grants } = this.options;
    this.upRule = force;
    const result = await this.create(roles, permissions, grants, force);
    this.upRule = false;

    return result;
  }

  /** Get instance of Role or Permission by his name */
  get(name: R | GrantType<A, RS>, forceRole = false): Promise<Base<R, A, RS> | undefined> {
    if (forceRole) {
      return this.createRole(name as R, false);
    }

    return this.storage.get(name);
  }

  /**  Return instance of Role by his name */
  getRole(name: R): Promise<Role<R, A, RS> | undefined> {
    return this.storage.getRole(name);
  }

  /** Return all instances of Role */
  getRoles(): Promise<Role<R, A, RS>[]> {
    return this.storage.getRoles();
  }

  /** Return instance of Permission by his action and resource */
  getPermission(action: A, resource: RS): Promise<Permission<R, A, RS> | undefined> {
    return this.storage.getPermission(action, resource);
  }

  /** Return instance of Permission by his name */
  getPermissionByName(name: GrantType<A, RS>): Promise<Permission<R, A, RS> | undefined> {
    const data = Permission.decodeName(name, this.options.delimiter);
    return this.storage.getPermission(data.action as A, data.resource as RS);
  }

  /** Return all instances of Permission */
  getPermissions(): Promise<Permission<R, A, RS>[]> {
    return this.storage.getPermissions();
  }

  /** Return array of all permission assigned to role of RBAC */
  async getScope(roleName: R): Promise<Base<R, A, RS>['name'][]> {
    const scope: Base<R, A, RS>['name'][] = [];

    // traverse hierarchy
    await this.traverseGrants({
      roleName: roleName,
      handle: async item => {
        if (item instanceof Permission && !scope.includes(item.name)) {
          scope.push(item.name);
        }

        return null;
      },
    });

    return scope;
  }

  /** Register role or permission to actual RBAC instance */
  add(item: Base<R, A, RS>): Promise<boolean> {
    if (!item) {
      throw new Error('Item is undefined');
    }

    if (item.rbac !== this) {
      throw new Error('Item is associated to another RBAC instance');
    }

    if (item.name === Role.sudoName && !this.upRule) {
      throw new Error(`Forbidden add item '${item.name}'`);
    }

    return this.storage.add(item);
  }

  /** Create multiple permissions and roles in one step */
  async create(
    roleNames: R[],
    permissionNames: PermissionType<RS, A>,
    grantsData?: GrantsType<R, A, RS>,
    force: boolean = false,
  ): Promise<RBACType> {
    this.upRule = force;

    const [permissions, roles] = await Promise.all([
      this.createPermissions(permissionNames),
      this.createRoles(roleNames),
    ]);

    if (grantsData) {
      await this.grants(grantsData);
    }

    this.upRule = false;

    return {
      permissions,
      roles,
    };
  }

  /** Create a new role assigned to actual instance of RBAC */
  async createRole(roleName: R, add = true): Promise<Role<R, A, RS>> {
    const role = new Role(this, roleName);
    if (add) {
      await role.add();
    }

    return role;
  }

  /** Create multiple roles in one step assigned to actual instance of RBAC */
  async createRoles(roleNames: R[], add = true): Promise<Record<string, Role<R, A, RS>>> {
    const roles: Record<string, Role<R, A, RS>> = {};
    await Promise.all(
      roleNames.map(async roleName => {
        const role = await this.createRole(roleName, add);

        roles[role.name] = role;
      }),
    );

    return roles;
  }

  /** Create a new permission assigned to actual instance of RBAC */
  async createPermission(action: A, resource: RS, add = true): Promise<Permission<R, A, RS>> {
    const permission = new Permission(this, action, resource);
    if (add) {
      await permission.add();
    }

    return permission;
  }

  /** Create multiple permissions in one step */
  async createPermissions(resources: PermissionType<RS, A>, add = true): Promise<Record<string, Permission<R, A, RS>>> {
    if (!isPlainObject(resources)) {
      throw new Error('Resources is not a plain object');
    }

    const permissions: Record<string, Permission<R, A, RS>> = {};

    for (const [resource, actions] of Object.entries(resources) as [RS, A[]][]) {
      for (const action of actions) {
        const permission = await this.createPermission(action, resource as RS, add);
        permissions[permission.name] = permission;
      }
    }

    return permissions;
  }

  /** Grant permission or role to the role */
  grant(role: Role<R, A, RS>, child: Base<R, A, RS>): Promise<boolean> {
    if (role.rbac !== this || child.rbac !== this) {
      throw new Error('Item is associated to another RBAC instance');
    }

    if (child.name === Role.sudoName && !this.upRule) {
      throw new Error(`Forbidden grant rule '${child.name}'`);
    }

    return this.storage.grant(role, child);
  }

  /** Grant permission or role from the role by names */
  async grantByName(roleName: R, childName: R | GrantType<A, RS>): Promise<boolean> {
    const [role, child] = await Promise.all([
      this.get(roleName, roleName === Role.sudoName && !this.upRule),
      this.get(childName),
    ]);

    this.checkItems(role?.name, child?.name);

    return await this.grant(role as Role<R, A, RS>, child as Base<R, A, RS>);
  }

  /** Grant multiple items in one function */
  async grants(data: GrantsType<R, A, RS>): Promise<Partial<Record<R, unknown[][]>>> {
    if (!isPlainObject(data)) {
      throw new Error('Grants is not a plain object');
    }
    const results: Partial<Record<R, unknown[][]>> = {};

    for (const [roleName, grants] of Object.entries(data) as [R, (GrantType<A, RS> | R)[]][]) {
      const write = [];
      for (const grant of grants) {
        const isGrant = await this.grantByName(roleName as R, grant);
        write.push([grant, isGrant]);
      }

      results[roleName as R] = write;
    }

    return results;
  }

  /** Remove role or permission from RBAC */
  remove(item: Base<R, A, RS>): Promise<boolean> {
    if (!item) {
      throw new Error('Item is undefined');
    }

    if (item.rbac !== this) {
      throw new Error('Item is associated to another RBAC instance');
    }

    if (item.name === Role.sudoName && !this.upRule) {
      throw new Error(`Forbidden remove item '${item.name}'`);
    }

    return this.storage.remove(item);
  }

  /** Remove role or permission from RBAC */
  async removeByName(name: R | GrantType<A, RS>): Promise<boolean> {
    const item = await this.get(name);
    if (!item) {
      return true;
    }

    return item.remove();
  }

  /** Revoke permission or role from the role */
  revoke(role: Role<R, A, RS>, child: Base<R, A, RS>): Promise<boolean> {
    this.checkItems(role?.name, child?.name);

    if (role.rbac !== this || child.rbac !== this) {
      throw new Error('Item is associated to another RBAC instance');
    }

    if (role.name === Role.sudoName && !this.upRule) {
      throw new Error(`Forbidden revoke item '${role.name}'`);
    }

    return this.storage.revoke(role, child);
  }

  /** Revoke permission or role from the role by names */
  async revokeByName(roleName: R, childName: R | GrantType<A, RS>): Promise<boolean> {
    const [role, child] = await Promise.all([this.get(roleName), this.get(childName)]);

    this.checkItems(role?.name, child?.name);

    return this.revoke(role as Role<R, A, RS>, child as Base<R, A, RS>);
  }

  async deleteAll(): Promise<RBACType> {
    const permissions = await this.getPermissions();
    for (const permission of permissions) {
      await permission.remove();
      logger.log(`permission ${permission.name} deleted`);
    }

    const roles = await this.getRoles();

    for (const role of roles) {
      await role.remove();
      logger.log(`role ${role.name} deleted`);
    }

    return { roles: {}, permissions: {} };
  }

  /** Return true if role has allowed permission */
  async can(roleName: R, action: A, resource: RS): Promise<boolean> {
    const can = await this.traverseGrants({
      roleName: roleName,
      handle: async item => {
        if (item instanceof Permission && item.can(action, resource)) {
          return true;
        }

        return null;
      },
    });

    return can ?? false;
  }

  /** Check if the role has any of the given permissions. */
  async canAny(roleName: R, permissions: PermissionParam<A, RS>[]): Promise<boolean> {
    // prepare the names of permissions
    const permissionNames = RBAC.getPermissionNames(permissions, this.options?.delimiter);

    // traverse hierarchy
    const can = await this.traverseGrants({
      roleName: roleName,
      handle: async item => {
        if (item instanceof Permission && permissionNames.includes(item.name)) {
          return true;
        }

        return null;
      },
    });

    return can ?? false;
  }

  /** Check if the model has all the given permissions. */
  async canAll(roleName: R, permissions: PermissionParam<A, RS>[]): Promise<boolean> {
    // prepare the names of permissions
    const permissionNames = RBAC.getPermissionNames(permissions, this.options.delimiter);
    const founded: Partial<Record<R, boolean>> = {};
    let foundedCount = 0;

    // traverse hierarchy
    await this.traverseGrants({
      roleName: roleName,
      handle: async item => {
        if (item instanceof Permission && permissionNames.includes(item.name) && !founded[item.name as R]) {
          founded[item.name as R] = true;
          foundedCount += 1;

          if (foundedCount === permissionNames.length) {
            return true;
          }
        }

        return null;
      },
    });

    return foundedCount === permissionNames.length;
  }

  /** Callback returns true if role or permission exists */
  exists(name: R | GrantType<A, RS>): Promise<boolean> {
    return this.storage.exists(name);
  }

  /** Callback returns true if role exists */
  existsRole(name: R): Promise<boolean> {
    return this.storage.existsRole(name);
  }

  /** Callback returns true if permission exists */
  existsPermission(action: A, resource: RS): Promise<boolean> {
    return this.storage.existsPermission(action, resource);
  }

  /** Return true if role has allowed permission */
  async hasRole(roleName: R, roleChildName: R): Promise<boolean> {
    if (roleName === roleChildName) {
      return true;
    }

    const has = await this.traverseGrants({
      roleName: roleName,
      handle: async item => {
        if (item instanceof Role && item.name === roleChildName) {
          return true;
        }

        return null;
      },
    });

    return has ?? false;
  }

  /**
   * Traverse hierarchy of roles.
   * Callback function returns as second parameter item from hierarchy or null if we are on the end of hierarchy.
   * */
  private async traverseGrants({
    roleName,
    handle,
    next = [roleName],
    used = {},
  }: TraverseGrantsParams<R>): Promise<boolean | undefined> {
    const actualRole = next.shift();
    actualRole && (used[actualRole] = true);

    const grants = actualRole ? await this.storage.getGrants(actualRole) : [];
    for (let i = 0; i < grants.length; i += 1) {
      const item = grants[i];
      const { name } = item;

      if (item instanceof Role && !used[name as R]) {
        used[name as R] = true;
        next.push(name as R);
      }

      const result = await handle(item);
      if (result !== null) {
        return result;
      }
    }

    if (next.length) {
      return this.traverseGrants({ roleName: void 0, handle, next, used });
    }
  }

  private checkItems(role?: string, child?: string) {
    if (!role) {
      throw new Error(`Base role '${role}' is not exist`);
    }

    if (!child) {
      throw new Error(`Permission '${child}' is missing for grant or revoke`);
    }
  }
}
