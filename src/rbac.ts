import isPlainObject from 'lodash/isPlainObject';

import Base from './base';
import { GRAND_DELIMITER, RBAC_DEFAULT_OPTIONS } from './config/default';
import { Permission } from './permission';
import { Role } from './role';
import Storage from './storages';
import { MemoryStorage } from './storages/memory.storage';
import {
  ActionType,
  GrantsType,
  GrantType,
  PermissionParam,
  PermissionType,
  RBACOptionsType,
  RBACType,
  ResourceType,
  RoleType,
  TraverseGrantsParams,
} from './types';
import logger from './util/logger';

logger.mute(false);

const forbiddenError = new Error('Forbidden');

export class RBAC {
  public options: RBACOptionsType;
  private storage: Storage;

  #upRule = false;

  static Role: typeof Role;
  static Permission: typeof Permission;
  static Storage: typeof Storage;

  /** Convert Array of permissions to permission name */
  static getPermissionNames(permissions: PermissionParam[], delimiter: string = GRAND_DELIMITER): string[] {
    if (!delimiter) {
      throw new Error('Delimiter is not defined');
    }

    return permissions.map(([action, resource]) => Permission.createName(action, resource, delimiter));
  }

  constructor(options?: Partial<RBACOptionsType>) {
    this.options = {
      ...RBAC_DEFAULT_OPTIONS,
      ...options,
    };

    this.storage = <Storage>this.options.storage || new MemoryStorage();
    this.storage.useRBAC(this);
  }

  protected set upRule(value: boolean) {
    this.#upRule = value;
  }

  get upRule() {
    return this.#upRule;
  }

  async init() {
    const { roles, permissions, grants } = this.options;
    this.upRule = true;
    const result = await this.create(roles, permissions, grants);
    this.upRule = false;

    return result;
  }

  /** Get instance of Role or Permission by his name */
  get(name: RoleType | GrantType): Promise<Base | undefined> {
    return this.storage.get(name);
  }

  /**  Return instance of Role by his name */
  getRole(name: RoleType): Promise<Role | undefined> {
    return this.storage.getRole(name);
  }

  /** Return all instances of Role */
  getRoles(): Promise<Role[]> {
    return this.storage.getRoles();
  }

  /** Return instance of Permission by his action and resource */
  getPermission(action: ActionType, resource: ResourceType): Promise<Permission | undefined> {
    return this.storage.getPermission(action, resource);
  }

  /** Return instance of Permission by his name */
  getPermissionByName(name: GrantType): Promise<Permission | undefined> {
    const data = Permission.decodeName(name, this.options.delimiter);
    return this.storage.getPermission(data.action, data.resource);
  }

  /** Return all instances of Permission */
  getPermissions(): Promise<Permission[]> {
    return this.storage.getPermissions();
  }

  /** Return array of all permission assigned to role of RBAC */
  async getScope(roleName: RoleType): Promise<Base['name'][]> {
    const scope: Base['name'][] = [];

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
  add(item: Base): Promise<boolean> {
    if (!item) {
      throw new Error('Item is undefined');
    }

    if (item.rbac !== this) {
      throw new Error('Item is associated to another RBAC instance');
    }

    if (item.name === Role.sudoName && !this.upRule) {
      throw forbiddenError;
    }

    return this.storage.add(item);
  }

  /** Create multiple permissions and roles in one step */
  async create(roleNames: RoleType[], permissionNames: PermissionType, grantsData?: GrantsType): Promise<RBACType> {
    const [permissions, roles] = await Promise.all([
      this.createPermissions(permissionNames),
      this.createRoles(roleNames),
    ]);

    if (grantsData) {
      await this.grants(grantsData);
    }

    return {
      permissions,
      roles,
    };
  }

  /** Create a new role assigned to actual instance of RBAC */
  async createRole(roleName: RoleType, add = true): Promise<Role> {
    const role = new Role(this, roleName);
    if (add) {
      await role.add();
    }

    return role;
  }

  /** Create multiple roles in one step assigned to actual instance of RBAC */
  async createRoles(roleNames: RoleType[], add = true): Promise<Record<string, Role>> {
    const roles: Record<string, Role> = {};
    await Promise.all(
      roleNames.map(async roleName => {
        const role = await this.createRole(roleName, add);

        roles[role.name] = role;
      }),
    );

    return roles;
  }

  /** Create a new permission assigned to actual instance of RBAC */
  async createPermission(action: ActionType, resource: ResourceType, add = true): Promise<Permission> {
    const permission = new Permission(this, action, resource);
    if (add) {
      await permission.add();
    }

    return permission;
  }

  /** Create multiple permissions in one step */
  async createPermissions(resources: PermissionType, add = true): Promise<Record<string, Permission>> {
    if (!isPlainObject(resources)) {
      throw new Error('Resources is not a plain object');
    }

    const permissions: Record<string, Permission> = {};

    for (const [resource, actions] of Object.entries(resources)) {
      for (const action of actions) {
        const permission = await this.createPermission(action, resource as ResourceType, add);
        permissions[permission.name] = permission;
      }
    }

    return permissions;
  }

  /** Grant permission or role to the role */
  grant(role: Role, child: Base): Promise<boolean> {
    if (role.rbac !== this || child.rbac !== this) {
      throw new Error('Item is associated to another RBAC instance');
    }

    if (child.name === Role.sudoName && !this.upRule) {
      throw forbiddenError;
    }

    return this.storage.grant(role, child);
  }

  /** Grant permission or role from the role by names */
  async grantByName(roleName: RoleType, childName: RoleType | GrantType): Promise<boolean> {
    const [role, child] = await Promise.all([this.get(roleName), this.get(childName)]);

    this.checkItems(role?.name, child?.name);

    return await this.grant(role as Role, child as Base);
  }

  /** Grant multiple items in one function */
  async grants(data: GrantsType): Promise<Partial<Record<RoleType, boolean[]>>> {
    if (!isPlainObject(data)) {
      throw new Error('Grants is not a plain object');
    }
    const results: Partial<Record<RoleType, boolean[]>> = {};

    for (const [roleName, grants] of Object.entries(data)) {
      const write = [];
      for (const grant of grants) {
        write.push(await this.grantByName(roleName as RoleType, grant));
      }

      results[roleName as RoleType] = write;
    }

    return results;
  }

  /** Remove role or permission from RBAC */
  remove(item: Base): Promise<boolean> {
    if (!item) {
      throw new Error('Item is undefined');
    }

    if (item.rbac !== this) {
      throw new Error('Item is associated to another RBAC instance');
    }

    if (item.name === Role.sudoName && !this.upRule) {
      throw forbiddenError;
    }

    return this.storage.remove(item);
  }

  /** Remove role or permission from RBAC */
  async removeByName(name: RoleType | GrantType): Promise<boolean> {
    const item = await this.get(name);
    if (!item) {
      return true;
    }

    return item.remove();
  }

  /** Revoke permission or role from the role */
  revoke(role: Role, child: Base): Promise<boolean> {
    this.checkItems(role?.name, child?.name);

    if (role.rbac !== this || child.rbac !== this) {
      throw new Error('Item is associated to another RBAC instance');
    }

    if (role.name === Role.sudoName && !this.upRule) {
      throw forbiddenError;
    }

    return this.storage.revoke(role, child);
  }

  /** Revoke permission or role from the role by names */
  async revokeByName(roleName: RoleType, childName: RoleType | GrantType): Promise<boolean> {
    const [role, child] = await Promise.all([this.get(roleName), this.get(childName)]);

    this.checkItems(role?.name, child?.name);

    return this.revoke(role as Role, child as Base);
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
  async can(roleName: RoleType, action: ActionType, resource: ResourceType): Promise<boolean> {
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
  async canAny(roleName: RoleType, permissions: PermissionParam[]): Promise<boolean> {
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
  async canAll(roleName: RoleType, permissions: PermissionParam[]): Promise<boolean> {
    // prepare the names of permissions
    const permissionNames = RBAC.getPermissionNames(permissions, this.options.delimiter);
    const founded: Partial<Record<RoleType, boolean>> = {};
    let foundedCount = 0;

    // traverse hierarchy
    await this.traverseGrants({
      roleName: roleName,
      handle: async item => {
        if (item instanceof Permission && permissionNames.includes(item.name) && !founded[item.name as RoleType]) {
          founded[item.name as RoleType] = true;
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
  exists(name: RoleType | GrantType): Promise<boolean> {
    return this.storage.exists(name);
  }

  /** Callback returns true if role exists */
  existsRole(name: RoleType): Promise<boolean> {
    return this.storage.existsRole(name);
  }

  /** Callback returns true if permission exists */
  existsPermission(action: ActionType, resource: ResourceType): Promise<boolean> {
    return this.storage.existsPermission(action, resource);
  }

  /** Return true if role has allowed permission */
  async hasRole(roleName: RoleType, roleChildName: RoleType): Promise<boolean> {
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
  }: TraverseGrantsParams): Promise<boolean | undefined> {
    const actualRole = next.shift();
    actualRole && (used[actualRole] = true);

    const grants = actualRole ? await this.storage.getGrants(actualRole) : [];
    for (let i = 0; i < grants.length; i += 1) {
      const item = grants[i];
      const { name } = item;

      if (item instanceof Role && !used[name as RoleType]) {
        used[name as RoleType] = true;
        next.push(name as RoleType);
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
