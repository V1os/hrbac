/* eslint-disable @typescript-eslint/ban-ts-comment */

import { RBACType, GrantsType, PermissionType } from './declarations/hrbac';
import { Permission } from './permission';
import { RBAC } from './rbac';
import Storage from './storages';
import { MemoryStorage } from './storages/memory.storage';
import { ActionType, ResourceNameType, RoleType } from './types';

describe(`RBAC memory storage`, () => {
  let rbac: RBAC<RoleType, ActionType, ResourceNameType>;
  let response: RBACType;
  const storage: Storage<RoleType, ActionType, ResourceNameType> = new MemoryStorage<
    RoleType,
    ActionType,
    ResourceNameType
  >();

  const permissions: Array<[ActionType, ResourceNameType]> = [
    ['create', 'page'],
    ['delete', 'user'],
    ['update', 'page'],
  ];

  const roles: RoleType[] = ['superadmin', 'admin', 'user', 'guest'];

  const grants: GrantsType<RoleType, ActionType, ResourceNameType> = {
    admin: ['user', 'delete_user'],
    user: ['create_page', 'update_page'],
  };

  const permissionsAsObject: PermissionType<ResourceNameType, ActionType> = {
    page: ['create', 'update'],
    user: ['delete'],
  };

  test('decode permission', () => {
    const decoded = Permission.decodeName('create_page', '_');

    expect(decoded).toBeDefined();

    expect(decoded.action).toBe('create');
    expect(decoded.resource).toBe('page');
  });

  test('should be able to create roles and permissions', async () => {
    rbac = new RBAC({ storage });
    const data = await rbac.create(roles, permissionsAsObject, void 0, true);
    expect(data).toBeDefined();

    response = data;
    // response.should.have.properties(['roles', 'permissions']);
    expect(Object.keys(data)).toEqual(expect.arrayContaining(['roles', 'permissions']));

    for (let i = 0; i < roles.length; i += 1) {
      const name = roles[i];
      expect(response.roles[name]).toBeDefined();

      const instance = response.roles[name];
      expect(instance.name).toBe(name);
    }

    for (let i = 0; i < permissions.length; i += 1) {
      const permission = permissions[i];
      const name = Permission.createName(permission[0], permission[1], '_');
      expect(response.permissions[name]).toBeDefined();

      // check name
      const instance = response.permissions[name];
      expect(instance.name).toBe(name);
    }
  });

  test('grant permissions for admin', async () => {
    const { admin } = response.roles;
    const deleteUser = response.permissions.delete_user;

    const granted = await admin.grant(deleteUser);
    expect(granted).toBe(true);
  });

  test('grant permissions for user', async () => {
    const { user } = response.roles;
    const createpage = response.permissions.create_page;
    await user.grant(createpage);
  });

  test('grant role for admin', async () => {
    const { admin, user } = response.roles;

    await admin.grant(user);
  });

  test('admin can create page', async () => {
    const { admin } = response.roles;

    const can = await admin.can('create', 'page');
    expect(can).toBe(true);
  });

  test('admin can delete user', async () => {
    const { admin } = response.roles;

    const can = await admin.can('delete', 'user');
    expect(can).toBe(true);
  });

  test('user can not delete user', async () => {
    const { user } = response.roles;

    const can = await user.can('delete', 'user');
    expect(can).toBe(false);
  });

  test('user can create page', async () => {
    const { user } = response.roles;

    const can = await user.can('create', 'page');
    expect(can).toBe(true);
  });

  test('user can any create page', async () => {
    const { user } = response.roles;

    const can = await user.canAny(permissions);
    expect(can).toBe(true);
  });

  test('user can all create page', async () => {
    const { user } = response.roles;

    const can = await user.canAll(permissions);
    expect(can).toBe(false);
  });

  test('admin can all create page', async () => {
    const { admin } = response.roles;

    await rbac.grants(grants);
    const can = await admin.canAll(permissions);
    expect(can).toBe(true);
  });

  test('should be able to get role', async () => {
    const admin = await rbac.getRole('admin');
    expect(admin?.name).toBe('admin');
  });

  test('should not be able to get permission through getRole', async () => {
    // @ts-ignore
    const permission = await rbac.getRole('create_page');
    expect(permission).toBeUndefined();
  });

  test('should be able to get permission', async () => {
    const permission = await rbac.getPermission('create', 'page');
    expect(permission?.name).toBe('create_page');
  });

  test('should not be able to get role through getPermission', async () => {
    // @ts-ignore
    await expect(rbac.getPermission('admin', '')).rejects.toEqual(new Error('Resource is not defined'));
  });

  test('should able to revoke permission', async () => {
    const revoked = await rbac.revokeByName('user', 'create_page');
    expect(revoked).toBe(true);
  });

  test('user can not create page because it is revoked', async () => {
    const { user } = response.roles;

    const can = await user.can('create', 'page');
    expect(can).toBe(false);
  });

  test('should able to grant permission again', async () => {
    const granted = await rbac.grantByName('user', 'create_page');
    expect(granted).toBe(true);
  });

  test('user can create page because it is granted again', async () => {
    const { user } = response.roles;

    const can = await user.can('create', 'page');
    expect(can).toBe(true);
  });

  test('should be able to get role', async () => {
    const user = await rbac.get('user');
    expect(user?.name).toBe('user');
  });

  test('should be able to get permission', async () => {
    const permission = await rbac.get('create_page');
    expect(permission?.name).toBe('create_page');
  });

  test('should be able to remove permission', async () => {
    const removed = await rbac.remove(response.permissions.create_page);
    expect(removed).toBe(true);
  });

  test('should not be able to get removed permission', async () => {
    const permission = await rbac.get('create_page');
    expect(permission).toBeUndefined();
  });

  test('should be able to remove role', async () => {
    const removed = await rbac.remove(response.roles.guest);
    expect(removed).toBe(true);
  });

  test('should not be able to get removed role', async () => {
    const role = await rbac.get('guest');
    expect(role).toBeUndefined();
  });

  test('should be able to remove permission by name', async () => {
    const removed = await rbac.removeByName('delete_user');
    expect(removed).toBe(true);
  });

  test('should not be able to get removed permission', async () => {
    const permission = await rbac.get('delete_user');
    expect(permission).toBeUndefined();
  });

  test('should able to check existance of role', async () => {
    const exists = await rbac.exists('admin');
    expect(exists).toBe(true);
  });

  test('should able to check existance of non exist role', async () => {
    // @ts-ignore
    const exists = await rbac.exists('adminooooo');
    expect(exists).toBe(false);
  });

  test('should able to check existance of role', async () => {
    const exists = await rbac.existsRole('admin');
    expect(exists).toBe(true);
  });

  test('should able to check existance of permission', async () => {
    const exists = await rbac.existsPermission('update', 'page');
    expect(exists).toBe(true);
  });

  test('should be able to create roles and permissions with constructor', async () => {
    const localrbac = new RBAC<RoleType, ActionType, ResourceNameType>({
      roles,
      // @ts-ignore
      permissions: permissionsAsObject,
      grants,
    });

    await localrbac.init();

    rbac = localrbac;

    expect(localrbac).toBeDefined();
  });

  test('should be able to get scope for admin', async () => {
    const scope = await rbac.getScope('admin');
    expect(scope).toEqual(expect.arrayContaining(['delete_user', 'create_page', 'update_page']));
  });

  test('should be able to get scope for user', async () => {
    const scope = await rbac.getScope('user');
    expect(scope).toEqual(expect.arrayContaining(['create_page', 'update_page']));
  });

  test('should be able to get scope for more complex object', async () => {
    const localRBAC = new RBAC<RoleType, ActionType, ResourceNameType>({
      roles: ['superadmin', 'admin', 'user', 'guest'],
      permissions: {
        user: ['create', 'delete'],
        // @ts-ignore
        password: ['change', 'forgot'],
        page: ['create'],
        rbac: ['update'],
      },
      grants: {
        // @ts-ignore
        guest: ['create_user', 'forgot_password'],
        // @ts-ignore
        user: ['change_password'],
        // @ts-ignore
        admin: ['user', 'delete_user', 'update_rbac', 'create_page'],
        superadmin: ['admin'],
      },
    });

    await localRBAC.init();

    const scope = await localRBAC.getScope('admin');
    expect(scope).toEqual(expect.arrayContaining(['delete_user', 'update_rbac', 'create_page', 'change_password']));
  });
});
