import { DecodeNamePermissionType, DelimiterType, GrantType } from 'hrbac';

import Base from './base';
import { GRAND_DELIMITER } from './config/default';
import { RBAC } from './rbac';

export class Permission<R extends string, A extends string, RS extends string> extends Base<R, A, RS> {
  #action: A;
  #resource: RS;

  /** Compute name of permission from action and resource */
  static createName<A extends string, RS extends string>(
    action: A,
    resource: RS,
    delimiter: DelimiterType = GRAND_DELIMITER,
  ): GrantType<A, RS> {
    if (!delimiter) {
      throw new Error('Delimiter is not defined');
    }

    if (!action) {
      throw new Error('Action is not defined');
    }

    if (!resource) {
      throw new Error('Resource is not defined');
    }

    return `${action}${delimiter}${resource}` as GrantType<A, RS>;
  }

  static decodeName<A extends string, RS extends string>(
    name: GrantType<A, RS>,
    delimiter: DelimiterType = GRAND_DELIMITER,
  ): DecodeNamePermissionType<A, RS> {
    if (!delimiter) {
      throw new Error('delimiter is required');
    }

    if (!name) {
      throw new Error('Name is required');
    }

    const pos = name.indexOf(delimiter);
    if (pos === -1) {
      throw new Error('Wrong name');
    }

    return {
      action: name.slice(0, pos) as A,
      resource: name.slice(pos + 1) as RS,
    };
  }

  /**  Permission constructor  */
  constructor(rbac: RBAC<R, A, RS>, action: A, resource: RS) {
    if (!action || !resource) {
      throw new Error('One of parameters is undefined');
    }

    if (
      !Permission.isValidName(action, rbac.options.delimiter) ||
      !Permission.isValidName(resource, rbac.options.delimiter)
    ) {
      throw new Error('Action or resource has no valid name');
    }

    super(rbac, Permission.createName(action, resource, rbac.options.delimiter));

    this.#action = action;
    this.#resource = resource;
  }

  /** Get action name of actual permission */
  get action(): A {
    if (!this.#action) {
      const decoded = Permission.decodeName<A, RS>(this.name as GrantType<A, RS>, this.rbac.options.delimiter);
      if (!decoded) {
        throw new Error('Action is null');
      }

      this.#action = decoded.action;
    }

    return this.#action;
  }

  /** Get resource name of actual permission */
  get resource(): RS {
    if (!this.#resource) {
      const decoded = Permission.decodeName<A, RS>(this.name as GrantType<A, RS>, this.rbac.options.delimiter);
      if (!decoded) {
        throw new Error('Resource is null');
      }

      this.#resource = decoded.resource;
    }

    return this.#resource;
  }

  /** Return true if it has same action and resource */
  can(action: A, resource: RS): boolean {
    return this.action === action && this.resource === resource;
  }

  /** Correct name can not contain whitespace or underscores. */
  static isValidName(name: string, delimiter: DelimiterType = GRAND_DELIMITER): boolean {
    if (!delimiter) {
      throw new Error('Delimiter is not defined');
    }

    const exp = new RegExp(`^[^${delimiter}\\s]+$`);

    return exp.test(name);
  }
}
