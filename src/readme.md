# Rancagua Digital Moleculer Auth Mixin

## Description

Moleculer Mixin to provide a _authentication_ and _authorization_ capabilities to _[Moleculer](https://moleculer.services)_ microservices.

## Installation

`npm install services-auth-mixin`
or
`yarn add services-auth-mixin`

## Usage

When defining your _[Moleculer](https://moleculer.services)_ service add the _Auth_ as a mixin:

```javascript
const Auth = require('services-auth-mixin')

module.exports = {
  name: '<service-name>',
  version: 1,

  mixins: [Auth],
  ...
}
  ```
