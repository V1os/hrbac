import { GrantType, EnumValueType, GenerateRuleModesType } from 'hrbac';

import { ActionEnum } from '../enums';
import { ActionType, ResourceNameType, RoleType } from '../types';

type WindGrantType = GrantType<ActionType, ResourceNameType> | RoleType;

export const windGrant = <R extends EnumValueType, A extends EnumValueType, RS extends EnumValueType>(
  options: Partial<Record<RS, GenerateRuleModesType<A | R>>>,
  delimiter = '_',
): WindGrantType[] => {
  const grants: WindGrantType[] = [];

  for (const [resource, rules = 'R'] of Object.entries(options) as [RS, (A | R)[]][]) {
    for (const rule of rules as unknown as ActionType[]) {
      if (!(rule in ActionEnum)) {
        throw new Error('Cant find action resource');
      }
      grants.push(`${rule}${delimiter}${resource}` as WindGrantType);
    }
  }

  return grants;
};

// const grant = windGrant({
//   localizations: 'ABCD',
//   user: 'CRUD',
// });
