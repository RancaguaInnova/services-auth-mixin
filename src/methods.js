const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const intersection = require('lodash/intersection')
const startsWith = require('lodash/startsWith')
const {
  MoleculerClientError,
  MoleculerServerError
} = require('moleculer').Errors

const UNAUTHORIZED_ERROR = new MoleculerClientError(
  'User does not have the required permissions',
  403,
  'Forbidden'
)

/**
 * Get the authorization token from a request object
 *
 * @param {object} request Moleculer/Node request object
 * @returns {object} With the auth type as key, token as value
 */
const getToken = request => {
  const { headers, body, query } = request
  const secret = query && query.secret || false
  if (headers && headers.authorization) {
    const authType = startsWith(headers.authorization, 'Basic ')
      ? 'basic'
      : 'bearer'

    if (authType === 'basic') {
      return {
        basicToken: headers.authorization.slice(6)
      }
    } else {
      return {
        bearerToken: headers.authorization.slice(7)
      }
    }
  } else if ((!secret && ((body && body.token) || (query && query.token)))) {
    const paramsToken = body && body.token ? body.token : query.token
    return { paramsToken }
  }
  return {}
}

/**
 * Checks if the requesting user is authorized to access
 * based on dynamic role array.
 *
 * @param {Object} context Service/Action context information
 *
 * @returns
 */
function roleAccess (authorized = []) {
  return async function (context) {
    try {
      const { meta } = context
      const isAuthorized = intersection(meta.user.roles, authorized).length
      return isAuthorized > 0
        ? Promise.resolve(context)
        : Promise.reject(UNAUTHORIZED_ERROR)
    } catch (error) {
      return Promise.reject(UNAUTHORIZED_ERROR)
    }
  }
}

/**
 * Checks if the requesting user has a session/token.
 * Sets the token payload to context.meta if a session/token is found.
 *
 * @param {Object} context Service/Action context information
 *
 * @returns
 */
const isAuthenticated = async context => {
  try {
    const { origin } = context.meta
    if (!context.meta.user) {
      return Promise.reject(UNAUTHORIZED_ERROR)
    } else if (context.meta.user) {
      let user = context.meta.user
      if (user.name && user.name === 'JsonWebTokenError') {
        return Promise.reject(UNAUTHORIZED_ERROR)
      }
      let d = new Date(user.expiresAt)
      d.setHours(d.getHours() + 4)
      let n = d.getTime()
      var fechaNow = Date.now()
      // FIX - session from app-flutter doesn`t expire @joseAbarcaSaavedra
      if (n < fechaNow && origin !== 'app-flutter') {
        return Promise.reject(UNAUTHORIZED_ERROR)
      }
      return Promise.resolve(context)
    }
  } catch (e) {
    console.log('e', e)
    return Promise.reject(UNAUTHORIZED_ERROR)
  }
}

const getUserDataFromToken = async function (context, tokenObj) {
  const token = Object.values(tokenObj)[0]

  try {
    return token
      ? await context.call('v1.auth.isTokenValid', {
        token
      })
      : null
  } catch (error) {
    this.logger.error('Error validating token:', error)
    return Promise.reject(UNAUTHORIZED_ERROR)
  }
}

/**
 * Checks that the requesting user has the required action role(s)
 *
 * @param {Object} context Service/Action context information
 */
const hasRole = async function (context) {
  try {
    const { action, meta } = context
    const isAuthorized =
      action.roles && intersection(meta.user.roles, action.roles).length
    // const isOwner = await this.isOwner(context)
    // FIX: hasRole only apply role validation @joseAbarcaSaavedra
    if (!isAuthorized /* && !isOwner */) {
      return Promise.reject(UNAUTHORIZED_ERROR)
    } else {
      return Promise.resolve(context)
    }
  } catch (error) {
    console.log('[hasRole]', error)
    return Promise.reject(UNAUTHORIZED_ERROR)
  }
}

/**
 * Check if the requesting user owns the requested resource
 *
 * @param {Object} context Service/Action context information
 */
const isOwner = async function (context) {
  const { user, resourceId } = context.meta
  if (user.id === resourceId) {
    return Promise.resolve(context)
  } else {
    return Promise.reject(UNAUTHORIZED_ERROR)
  }
}

/**
 * Check if the external invocation is authenticated
 * Used in cron-jobs
 *
 * @param {Object} context Service/Action context information
 */
const isExternalyAuthenticated = async function (context) {
  const { basicToken } = context.meta
  if (basicToken) {
    const bufferToken = Buffer.from(basicToken, 'base64').toString('ascii')
    const envToken = process.env.EXTERNAL_AUTH
    if (bufferToken === envToken) {
      return Promise.resolve(context)
    } else {
      return Promise.reject(UNAUTHORIZED_ERROR)
    }
  }
  return Promise.reject(UNAUTHORIZED_ERROR)
}

/**
 * Check passwords
 *
 * @param {String} password Password used on login
 *
 * @param {Object} user User entity
 *
 * @returns {Boolean} The password exists or not
 */
const checkPasswords = async function (password, user) {
  try {
    return await bcrypt.compare(password, user.services.password.bcrypt)
  } catch (error) {
    console.log('Could not compare passwords:', error.message)
    return Promise.reject(
      new MoleculerServerError(
        `Could not compare passwords: ${error.message}`,
        500,
        'InternalServerError'
      )
    )
  }
}

/**
 * Verify that the token is valid and return its payload
 *
 * @param {String} token Users bearer token
 *
 * @returns {Object} Users data / token payload
 */
const verifyToken = function (token) {
  return jwt.verify(
    token,
    process.env.JWT_SECRET,
    (error, payload = { data: null, id: null }) => {
      try {
        if (error) {
          return Promise.reject(error)
        }
        const data = payload.data
          ? payload.data
          : payload.id ? { ...payload } : null

        // Add default role @jabarca
        if (data.roles && data.roles.length === 0) {
          data.roles.push('user')
        }
        return data
      } catch (error) {
        return Promise.reject(error)
      }
    }
  )
}

/**
 * Checks if the user has verified his email
 *
 * @param {Object} user User entity
 *
 * @returns {Boolean} User has verified email or not
 */
const hasVerifiedEmail = function (user) {
  if (user.emails && user.emails[0].verified) {
    return true
  }
  return false
}

module.exports = {
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
