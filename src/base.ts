import { GrantType } from 'hrbac';

import type { RBAC } from './rbac';

export default class Base<R extends string, A extends string, RS extends string> {
  public name: R | GrantType<A, RS>;
  public rbac: RBAC<R, A, RS>;

  constructor(rbac: RBAC<R, A, RS>, name: R | GrantType<A, RS>) {
    if (!rbac || !name) {
      throw new Error('One of parameters is undefined');
    }

    this.name = name;
    this.rbac = rbac;
  }

  /** Add this to RBAC (storage) */
  async add(): Promise<boolean> {
    return this.rbac.add(this);
  }

  /**  Remove this from RBAC (storage) */
  async remove(): Promise<boolean> {
    return this.rbac.remove(this);
  }
}
