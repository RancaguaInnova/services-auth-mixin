'use strict'

const {
  checkPasswords,
  getToken,
  getUserDataFromToken,
  hasVerifiedEmail,
  isAuthenticated,
  isOwner,
  hasRole,
  roleAccess,
  isExternalyAuthenticated,
  verifyToken
} = require('./methods')

module.exports = {
  methods: {
    checkPasswords,
    getToken,
    getUserDataFromToken,
    hasVerifiedEmail,
    isAuthenticated,
    isOwner,
    hasRole,
    roleAccess,
    isExternalyAuthenticated,
    verifyToken
  }
}
