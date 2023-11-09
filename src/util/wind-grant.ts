import { ActionType, GrantType, ModeType, ResourceType, RoleType } from '../types';

type RMType = ModeType;
type RuleModesType =
  | `${RMType}`
  | `${RMType}${RMType}`
  | `${RMType}${RMType}${RMType}`
  | `${RMType}${RMType}${RMType}${RMType}`
  | `${RMType}${RMType}${RMType}${RMType}${RMType}`
  | `${RMType}${RMType}${RMType}${RMType}${RMType}${RMType}`;
type GrantsType = Record<ResourceType, RuleModesType>;

const modeMap: Record<RMType, ActionType> = {
  C: 'create',
  R: 'read',
  U: 'update',
  D: 'delete',
  B: 'block',
  N: 'cancel',
};

export const windGrant = (options: Partial<GrantsType>, delimiter = '_') => {
  const grants: (GrantType | RoleType)[] = [];

  for (const [resource, ruleModes = 'R'] of Object.entries(options)) {
    for (const mode of ruleModes as unknown as RMType[]) {
      if (!modeMap[mode]) {
        throw new Error('Cant find action resource');
      }
      grants.push(`${modeMap[mode]}${delimiter}${resource as ResourceType}`);
    }
  }

  return grants;
};
