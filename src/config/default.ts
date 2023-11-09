import { RBACOptionsType } from '../types';
import { windGrant } from '../util/wind-grant';

export const GRAND_DELIMITER = '_';

export const RBAC_DEFAULT_OPTIONS: RBACOptionsType = {
  permissions: {},
  roles: [],
  grants: {},
  delimiter: GRAND_DELIMITER,
};

export const initializeRBAC: RBACOptionsType = {
  roles: ['superadmin', 'admin', 'manager', 'user', 'guest'],
  permissions: {
    user: ['read', 'create', 'update', 'block'],
    guest: ['read', 'create'],
    role: ['read', 'create', 'update', 'delete'],
    permission: ['read', 'create', 'update', 'delete'],
  },
  grants: {
    user: windGrant({ user: 'R', guest: 'R' }),
    manager: windGrant({ user: 'CU' }).concat('user'),
    admin: windGrant({ user: 'B', guest: 'C' }).concat('manager'),
    superadmin: windGrant({ role: 'CRUD', permission: 'CRUD' }).concat('admin'),
  },
};
