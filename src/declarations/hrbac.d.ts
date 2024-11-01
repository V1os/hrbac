import type Base from '../base.ts';
import { TypeEnum } from '../enums';
import type { Permission } from '../permission.ts';
import type { Role } from '../role.ts';
import type Storage from '../storages';

declare module 'hrbac' {
  export type EnumValueType = string | number;

  export type ConcatType<T extends string[]> = T extends [infer F extends string, ...infer R extends string[]]
    ? `${F}${ConcatType<R>}`
    : '';

  export type DecodeNamePermissionType<A extends EnumValueType, RS extends EnumValueType> = {
    action: A;
    resource: RS;
  };

  export type PermissionParam<A extends EnumValueType, RS extends EnumValueType> = [
    DecodeNamePermissionType<A, RS>['action'],
    DecodeNamePermissionType<A, RS>['resource'],
  ];

  export type DelimiterType = string;

  export type PermissionType<RS extends EnumValueType, A extends EnumValueType> = Partial<Record<RS, A[]>>;

  export type GrantType<A extends EnumValueType, RS extends EnumValueType> = ConcatType<[A, DelimiterType, RS]>;

  export type GrantsType<R extends EnumValueType, A extends EnumValueType, RS extends EnumValueType> = Partial<
    Record<R, (GrantType<A, RS> | R)[]>
  >;

  // export type GenerateRuleModesType<
  //   ENUM extends EnumValueType,
  //   C1 extends string,
  //   C2 extends string = '',
  // > = C1 extends `${infer ACTION}${infer END}`
  //   ? GenerateRuleModesType<ENUM, END, `${C2}${ACTION extends ENUM ? ACTION : ''}`>
  //   : C2;
  export type GenerateRuleModesType<T extends EnumValueType> = T[];

  export enum AccessGrantTypeEnum {
    RESOURCE_DNE, // doesn't exist
    ACTION_DNE, // doesn't exist
    RESOURCE_CPA, // cannot perform an action
  }

  export type AccessGrantErrorType = {
    role: string;
    resource: string;
    action: string;
    type: AccessGrandTypeEnum;
  };

  export type RBACOptionsType<R extends EnumValueType, A extends EnumValueType, RS extends EnumValueType> = {
    permissions: PermissionType<RS, A>;
    roles: R[];
    grants: GrantsType<R, A, RS>;
    delimiter?: string;
    storage?: Storage;
  };

  export type RBACType = {
    permissions: Record<string, Permission>;
    roles: Record<string, Role>;
  };

  export type RBACPlaneType<R extends EnumValueType, A extends EnumValueType, RS extends EnumValueType> = {
    permissions: Record<string, GrantType<A, RS>>;
    roles: Record<string, R>;
  };

  type HandleTraverseGrantType = (item: Base) => Promise<boolean | null>;

  export interface TraverseGrantsParams<R extends EnumValueType> {
    roleName?: R;
    handle: HandleTraverseGrantType;
    next?: (R | undefined)[];
    used?: Partial<Record<R, boolean>>;
  }

  export type RecordType<R extends EnumValueType, A extends EnumValueType, RS extends EnumValueType> = {
    type: TypeEnum;
    name: R | GrantType<A, RS>;
    grants?: (R | GrantType<A, RS>)[];
  };

  export type MatrixPermissionsType<A extends EnumValueType, RS extends EnumValueType> = {
    actions: A[];
    resources: RS[];
    matrix: Record<A & 'resource-name', GrantType<A, RS> | null>[];
  };
}
