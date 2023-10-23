import { Permission } from './permission';
import { RBAC } from './rbac';
import { Role } from './role';
import Storage from './storages';
import { RedisStorage } from './storages/redis.storage';

RBAC.Role = Role;
RBAC.Permission = Permission;
RBAC.Storage = Storage;

export default RBAC;
export const rbac = new RBAC({ storage: new RedisStorage() });
