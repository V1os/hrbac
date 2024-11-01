import { PermissionParam } from 'hrbac';

import Base from './base';
import { Permission } from './permission';
import type { RBAC } from './rbac';

export class Role<R extends string, A extends string, RS extends string> extends Base<R, A, RS> {
  static readonly sudoName = 'superadmin';

  constructor(
    public rbac: RBAC<R, A, RS>,
    name: R,
  ) {
    if (!Permission.isValidName(name, rbac.options.delimiter)) {
      throw new Error('Role has no valid name');
    }

    super(rbac, name);
  }

  /**  Add role or permission to current role */
  async grant(item: Role<R, A, RS> | Permission<R, A, RS>): Promise<boolean> {
    return this.rbac.grant(this, item);
  }

  /** Remove role or permission from current role */
  async revoke(item: Role<R, A, RS> | Permission<R, A, RS>): Promise<boolean> {
    return this.rbac.revoke(this, item);
  }

  /** Return true if contains permission */
  async can(action: A, resource: RS): Promise<boolean> {
    return this.rbac.can(this.name as R, action, resource);
  }

  /** Check if the role has any of the given permissions */
  async canAny(permissions: PermissionParam<A, RS>[]): Promise<boolean> {
    return this.rbac.canAny(this.name as R, permissions);
  }

  /** Check if the model has all the given permissions */
  async canAll(permissions: PermissionParam<A, RS>[]): Promise<boolean> {
    return this.rbac.canAll(this.name as R, permissions);
  }

  /** Return true if the current role contains the specified role name */
  async hasRole(roleChildName: R): Promise<boolean> {
    return this.rbac.hasRole(this.name as R, roleChildName);
  }

  /** Return array of permission assigned to actual role */
  async getScope(): Promise<Base<R, A, RS>['name'][]> {
    return this.rbac.getScope(this.name as R);
  }
}
