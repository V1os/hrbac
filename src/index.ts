import { Permission } from './permission';
import { RBAC } from './RBAC';
import { Role } from './role';
import Storage from './storages';

RBAC.Role = Role;
RBAC.Permission = Permission;
RBAC.Storage = Storage;

export default RBAC;
