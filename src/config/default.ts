import { RBACOptionsType } from 'hrbac';

import { ActionType, ResourceNameType, RoleType } from '../types';
import { windGrant } from '../utils/wind-grant';

const rules = (params: Parameters<typeof windGrant<RoleType, ActionType, ResourceNameType>>[0]) => windGrant(params);

export const GRAND_DELIMITER = '_';

export const RBAC_DEFAULT_OPTIONS = {
  permissions: {},
  roles: [],
  grants: {},
  delimiter: GRAND_DELIMITER,
};

export const initializeRBAC: RBACOptionsType<RoleType, ActionType, ResourceNameType> = {
  roles: ['superadmin', 'admin', 'user'],
  permissions: {
    user: ['read', 'create', 'update'],
    page: ['read', 'delete'],
    text: ['read', 'create', 'update'],
  },
  grants: {
    user: rules({ user: ['read'], page: ['read'] }),
    admin: rules({ user: ['create', 'update'], page: ['create', 'update'] }).concat('user'),
    superadmin: rules({ user: ['delete'], page: ['delete'], text: ['delete'] }).concat('admin'),
  },
};
