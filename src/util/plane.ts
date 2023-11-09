import { Permission } from '../permission';
import { Role } from '../role';
import {
  RBACPlaneType,
  RBACType,
  RoleType,
  GrantType,
  MatrixPermissionsType,
  ActionType,
  ResourceType,
} from '../types';

// const createArray = (length: number) => [...new Array(length).keys()];

export const planeRBAC = (res: RBACType): RBACPlaneType =>
  Object.entries(res).reduce(
    (acc, [key, entries]) => ({
      ...acc,
      [key]: Object.keys(entries),
    }),
    {} as RBACPlaneType,
  );

export const planeRecordRoles = (res: Record<string, Role>): RoleType[] => Object.keys(res) as RoleType[];

export const planeRoles = (res: Role[]): RoleType[] =>
  Object.values(res)
    .map(role => role.name)
    .sort() as RoleType[];

export const planeRecordPermissions = (res: Record<string, Permission>): GrantType[] => Object.keys(res) as GrantType[];

export const planePermissions = (res: Permission[]): GrantType[] =>
  Object.values(res)
    .map(permission => permission.name)
    .sort() as GrantType[];

export const matrixPermissions = (permissions: Permission[]): MatrixPermissionsType => {
  const matrix: MatrixPermissionsType['matrix'] = [];
  const listActions: Set<ActionType> = new Set();
  const listResources: Set<ResourceType> = new Set();
  let listPermissions: GrantType[] = [];

  permissions.forEach(permission => {
    const { action, resource } = Permission.decodeName(permission.name as GrantType);
    listActions.add(action);
    listResources.add(resource);
    listPermissions.push(permission.name as GrantType);
  });

  const actions = Array.from(listActions);
  const resources = Array.from(listResources);

  for (const idx in resources) {
    const resource = resources[idx];

    for (const idy in actions) {
      const action = actions[idy];

      const name = Permission.createName(action, resource);
      const isValid = listPermissions.includes(name);

      if (isValid) {
        listPermissions = listPermissions.filter(p => p !== name);
      }

      if (!matrix[idx]) {
        matrix[idx] = {
          'resource-name': resource,
        };
      }

      matrix[idx] = {
        ...matrix[idx],
        [action]: isValid ? name : null,
      };
    }
  }

  return { actions, resources, matrix };
};
