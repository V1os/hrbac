/* eslint-disable @typescript-eslint/ban-ts-comment */
import { AccessGrandErrorClass } from '../access-grant-error.ts';
import { PermissionType, GrantsType, AccessGrantTypeEnum, AccessGrantErrorType } from '../declarations/hrbac';
import { ActionEnum, ResourceEnum } from '../enums';
import { ActionType, ResourceNameType, RoleType } from '../types';

export const isIntegrity = (
  permissions: PermissionType<ResourceNameType, ActionType>,
  grants: Partial<GrantsType<ResourceNameType, ActionType, RoleType>>,
) => {
  const roles = Object.keys(grants) as RoleType[];
  const errors: AccessGrantErrorType[] = [];

  for (const [role, grantPermissions] of Object.entries(grants)) {
    for (const grantPermission of grantPermissions) {
      if (roles.includes(grantPermission as RoleType)) {
        continue;
      }

      const pos = grantPermission.indexOf('_');
      const action = grantPermission.slice(0, pos) as ActionType;
      const resource = grantPermission.slice(pos + 1) as ResourceNameType;

      // @ts-ignore
      if (!Object.values(ResourceEnum).includes(resource)) {
        errors.push({
          role,
          resource,
          action,
          type: AccessGrantTypeEnum.RESOURCE_DNE,
        });
      }

      // @ts-ignore
      if (!Object.values(ActionEnum).includes(action)) {
        errors.push({
          role,
          resource,
          action,
          type: AccessGrantTypeEnum.ACTION_DNE,
        });
      }

      if (permissions[resource]?.includes(action) === false) {
        errors.push({
          role,
          resource,
          action,
          type: AccessGrantTypeEnum.RESOURCE_CPA,
        });
      }
    }
  }

  if (errors.length > 0) {
    throw new AccessGrandErrorClass('Incorrect rules', errors);
  }
};
