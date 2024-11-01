import { RBACType, RBACPlaneType, GrantType, MatrixPermissionsType } from 'hrbac';

import { Permission } from '../permission';
import { Role } from '../role';

export const planeRBAC = <R extends string, A extends string, RS extends string>(
  res: RBACType,
): RBACPlaneType<R, A, RS> =>
  Object.entries(res).reduce(
    (acc, [key, entries]) => ({
      ...acc,
      [key]: Object.keys(entries),
    }),
    {} as RBACPlaneType<R, A, RS>,
  );

export const planeRecordRoles = <R extends string, A extends string, RS extends string>(
  res: Record<string, Role<R, A, RS>>,
): R[] => Object.keys(res) as R[];

export const planeRoles = <R extends string, A extends string, RS extends string>(res: Role<R, A, RS>[]): R[] =>
  Object.values(res)
    .map(role => role.name)
    .sort() as R[];

export const planeRecordPermissions = <R extends string, A extends string, RS extends string>(
  res: Record<string, Permission<R, A, RS>>,
): GrantType<A, RS>[] => Object.keys(res) as GrantType<A, RS>[];

export const planePermissions = <R extends string, A extends string, RS extends string>(
  res: Permission<R, A, RS>[],
): GrantType<A, RS>[] =>
  Object.values(res)
    .map(permission => permission.name)
    .sort() as GrantType<A, RS>[];

export const matrixPermissions = <R extends string, A extends string, RS extends string>(
  permissions: Permission<R, A, RS>[],
): MatrixPermissionsType<A, RS> => {
  const matrix: MatrixPermissionsType<A, RS>['matrix'] = [];
  const listActions: Set<A> = new Set();
  const listResources: Set<RS> = new Set();
  let listPermissions: GrantType<A, RS>[] = [];

  permissions.forEach(permission => {
    const { action, resource } = Permission.decodeName(permission.name as GrantType<A, RS>);
    listActions.add(action as A);
    listResources.add(resource as RS);
    listPermissions.push(permission.name as GrantType<A, RS>);
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
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
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
