import indexOf from 'lodash/indexOf';
import union from 'lodash/union';
import without from 'lodash/without';
import { Schema } from 'mongoose';

import { RBAC } from '../rbac';
import { ActionType, GrantType, ResourceType, RoleType } from '../types';

type ShapeSchema = {
  permissions: GrantType[];
  role: RoleType;
};

type OptionPluginType = {
  defaultPermissions?: ShapeSchema['permissions'];
  defaultRole?: ShapeSchema['role'];
};
type MethodsContextType = Schema<ShapeSchema>['methods'];

/** Check if user has assigned a specific permission */
async function can(this: MethodsContextType, rbac: RBAC, action: ActionType, resource: ResourceType) {
  // check for exist of permission
  const permission = await rbac.getPermission(action, resource);

  if (!permission) {
    return false;
  }

  // check user additional permissions
  if (indexOf(this.permissions, permission.name) !== -1) {
    return true;
  }

  if (!this.role) {
    return false;
  }

  // check permission inside user role
  return await rbac.can(this.role, action, resource);
}

/** Assign additional permissions to the user */
async function addPermission(this: MethodsContextType, rbac: RBAC, action: ActionType, resource: ResourceType) {
  const permission = await rbac.getPermission(action, resource);
  if (!permission) {
    throw new Error('Permission not exists');
  }

  if (indexOf(this.permissions, permission.name) !== -1) {
    throw new Error('Permission is already assigned');
  }

  this.permissions.push(permission.name);

  const user = await this.save();

  if (!user) {
    throw new Error('User is undefined');
  }

  return true;
}

async function removePermission(this: MethodsContextType, permissionName: GrantType) {
  if (indexOf(this.permissions, permissionName) === -1) {
    throw new Error('Permission was not assigned!');
  }

  this.permissions = without(this.permissions, permissionName);
  const user = await this.save();

  if (!user) {
    throw new Error('User is undefined');
  }

  if (indexOf(user.permissions, permissionName) !== -1) {
    throw new Error('Permission was not removed');
  }

  return true;
}

/** Check if user has assigned a specific role */
async function hasRole(this: MethodsContextType, rbac: RBAC, role: RoleType) {
  if (!this.role) {
    return false;
  }

  // check for exist of permission
  return rbac.hasRole(this.role, role);
}

async function removeRole(this: MethodsContextType) {
  if (!this.role) {
    return false;
  }

  this.role = null;
  const user = await this.save();

  if (!user) {
    throw new Error('User is undefined');
  }

  return user.role === null;
}

async function setRole(this: MethodsContextType, rbac: RBAC, roleName: RoleType) {
  if (this.role === roleName) {
    throw new Error('User already has assigned this role');
  }

  // check for exist of permission
  const role = await rbac.getRole(roleName);

  if (!role) {
    throw new Error('Role does not exists');
  }

  this.role = role?.name;
  const user = await this.save();

  if (!user) {
    throw new Error('User is undefined');
  }

  return user.role === this.role;
}

async function getScope(this: MethodsContextType, rbac: RBAC) {
  const permissions = this.permissions || [];

  const scope = await rbac.getScope(this.role);

  return union(permissions, scope);
}

async function removeRoleFromCollection(this: MethodsContextType, roleName: RoleType) {
  await this.update(
    {
      role: roleName,
    },
    {
      role: null,
    },
    {
      multi: true,
    },
  );

  return true;
}

async function removePermissionFromCollection(this: MethodsContextType, permissionName: GrantType) {
  await this.update(
    {
      permissions: permissionName,
    },
    {
      $pull: {
        permissions: permissionName,
      },
    },
    {
      multi: true,
    },
  );

  return true;
}

export default function hRBACPlugin(schema: Schema<ShapeSchema>, options: OptionPluginType = {}) {
  schema.add({
    role: {
      type: String,
      default: options.defaultRole,
    },
    permissions: {
      type: [String],
      default: options.defaultPermissions,
    },
  });

  schema.methods.can = can;

  schema.methods.addPermission = addPermission;
  schema.methods.removePermission = removePermission;

  schema.methods.hasRole = hasRole;
  schema.methods.removeRole = removeRole;
  schema.methods.setRole = setRole;

  schema.methods.getScope = getScope;

  schema.statics.removeRoleFromCollection = removeRoleFromCollection;
  schema.statics.removePermissionFromCollection = removePermissionFromCollection;
}
