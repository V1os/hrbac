import Base from './base';
import { Permission } from './permission';
import { Role } from './role';
import Storage from './storages';

export type DecodeNamePermissionType = {
  action: ActionType;
  resource: ResourceType;
};
export type PermissionParam = [DecodeNamePermissionType['action'], DecodeNamePermissionType['resource']];
export type ResourceType = 'article' | 'user' | 'guest' | 'role' | 'permission' | 'settings' | 'order';
export type ModeType = 'C' | 'R' | 'U' | 'D' | 'B' | 'N';
export enum ResourceEnum {
  ARTICLE = 'article',
  USER = 'user',
  SETTINGS = 'settings',
  ROLE = 'role',
  PERMISSION = 'permission',
  ORDER = 'order',
}
export enum ActionEnum {
  C = 'create',
  R = 'read',
  U = 'update',
  D = 'delete',
  B = 'block',
  N = 'cancel',
}
export type ActionType = `${ActionEnum}`;
export type RoleType = 'superadmin' | 'admin' | 'manager' | 'user' | 'guest';
export type DelimiterType = string;
export type PermissionType = Partial<Record<ResourceType, ActionType[]>>;
export type GrantType = ConcatType<[ActionType, DelimiterType, ResourceType]>;
export type GrantsType = Partial<Record<RoleType, (GrantType | RoleType)[]>>;

export type RBACOptionsType = {
  permissions: PermissionType;
  roles: RoleType[];
  grants: GrantsType;
  delimiter?: string;
  storage?: Storage;
};

export type RBACType = {
  permissions: Record<string, Permission>;
  roles: Record<string, Role>;
};

export type RBACPlaneType = {
  permissions: Record<string, GrantType>;
  roles: Record<string, RoleType>;
};

type HandleTraverseGrantType = (item: Base) => Promise<boolean | null>;

export interface TraverseGrantsParams {
  roleName?: RoleType;
  handle: HandleTraverseGrantType;
  next?: (RoleType | undefined)[];
  used?: Partial<Record<RoleType, boolean>>;
}

export enum TypeEnum {
  PERMISSION = 'Permission',
  ROLE = 'Role',
}

export type RecordType = {
  type: TypeEnum;
  name: RoleType | GrantType;
  grants?: (GrantType | RoleType)[];
};

export type MatrixPermissionsType = {
  actions: ActionType[];
  resources: ResourceType[];
  matrix: Record<ActionType & 'resource-name', GrantType | null>[];
};

type ConcatType<T extends string[]> = T extends [infer F extends string, ...infer R extends string[]]
  ? `${F}${ConcatType<R>}`
  : '';
