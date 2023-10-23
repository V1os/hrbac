import { GrantsType, PermissionType, RBACOptionsType, RoleType } from '../types';
import { windGrant } from '../util/wind-grant';

export const GRAND_DELIMITER = '_';

export const RBAC_DEFAULT_OPTIONS: RBACOptionsType = {
  permissions: {},
  roles: [],
  grants: {},
  delimiter: GRAND_DELIMITER,
};

export const initializeRBAC: [RoleType[], PermissionType, GrantsType] = [
  ['superadmin', 'admin', 'manager', 'user'],
  {
    client: ['read', 'create', 'update', 'block'],
    admin: ['read', 'create'],
    role: ['read', 'create', 'update', 'delete'],
    permission: ['read', 'create', 'update', 'delete'],
  },
  {
    user: windGrant({ client: 'R', admin: 'R' }),
    manager: windGrant({ client: 'CU' }).concat('user'),
    admin: windGrant({ client: 'B', admin: 'C' }).concat('manager'),
    superadmin: windGrant({ role: 'CRUD', permission: 'CRUD' }).concat('admin'),
  },
];
