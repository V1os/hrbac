import { AccessGrantTypeEnum, AccessGrantErrorType } from 'hrbac';

export class AccessGrandErrorClass extends Error {
  constructor(
    message: string,
    public errors: AccessGrantErrorType[] = [],
  ) {
    super(message);
    this.name = 'AccessGrandError';
    this.errors = errors;
  }

  toString() {
    return `${this.name}: ${this.message}\n${this.getStack().join(',\n')}`;
  }

  getStack() {
    return this.errors.map(e => this.accessGrandMessage(e));
  }

  accessGrandMessage({ role, type, resource, action }: AccessGrantErrorType) {
    const message = `Role '${role}':`;

    switch (type) {
      case AccessGrantTypeEnum.ACTION_DNE:
        return `${message} action '${action}' doesn't exist for resource '${resource}`;

      case AccessGrantTypeEnum.RESOURCE_CPA:
        return `${message} resource '${resource}' cannot perform an action '${action}'`;

      case AccessGrantTypeEnum.RESOURCE_DNE:
        return `${message} resource '${resource}' doesn't exist!`;

      default:
        return `${message} some thing error!`;
    }
  }
}
