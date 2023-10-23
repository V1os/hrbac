import { Permission } from '../permission';
import { Role } from '../role';
import { RBACPlaneType, RBACType, RoleType, GrantType } from '../types';

export const planeRBAC = (res: RBACType): RBACPlaneType =>
  Object.entries(res).reduce(
    (acc, [key, entries]) => ({
      ...acc,
      [key]: Object.keys(entries),
    }),
    {} as RBACPlaneType,
  );

export const planeRecordRoles = (res: Record<string, Role>): RoleType[] => Object.keys(res);

export const planeRoles = (res: Role[]): RoleType[] =>
  Object.values(res)
    .map(role => role.name)
    .sort();

export const planeRecordPermissions = (res: Record<string, Permission>): GrantType[] => Object.keys(res);

export const planePermissions = (res: Permission[]): GrantType[] =>
  Object.values(res)
    .map(permission => permission.name)
    .sort();
