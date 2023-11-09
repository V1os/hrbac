RBAC
----
> (Hierarchical Role Based Access Control)

hierarchical RBAC is the authorization library.

## Motivation

`ts` library for general use RBAC conception with storage

## Usage

```js
import {RBAC} from 'RBAC'; // ES5 var RBAC = require('rbac').default;

const roles = ['admin', 'user', 'guest'];

const permissions = {
  user:     ['create', 'delete'],
  password: ['change', 'forgot'],
  article:  ['create'],
  rbac:     ['update']
};

const grants = {
  guest:      ['create_user', 'forgot_password'],
  user:       ['change_password'],
  admin:      ['user', 'delete_user', 'update_rbac'],
  superadmin: ['admin']
};

// as class controller param `option`
const rbac = new RBAC({roles, permissions, grants});
await rbac.init();

// as fabric method `create`
const rbac = await new RBAC().create(roles, permissions, grants)

// How check on rule acces?
const {admin} = rbac.roles;
const action = 'create';
const resource = 'article';

// or - await rbac.can('admin', action, resource);
// or - admin = await rbac.getRole('admin')
if (await admin.can(action, resource)) {
  console.log('User role admin can create article!');
}

if (await admin.canAny([['create', 'article'], ['delete', 'live']])) {
  console.log('User role admin can create acticle!');
}

if (await admin.canAny([['create', 'article'], ['delete', 'live']])) {
  console.log('User role admin can create acticle!');
}

if (await admin.canAll([['create', 'article'], ['delete', 'user']])) {
  console.log('User role admin can create acticle and user delete!');
}

``` 

## Check permissions

```js
const can = await rbac.can('admin', 'create', 'article');
if (can) {
  console.log('Admin is able create article');
}

// or you can use instance of admin role
const admin = await rbac.getRole('admin');
if (!admin) {
  return console.log('Role does not exists');
}

const can = await admin.can('create', 'article');
if (can) {
  console.log('Admin is able create article');    
}
```

## Running Tests

```sh
npm run test
```

## Build

```sh
npm run build
```
