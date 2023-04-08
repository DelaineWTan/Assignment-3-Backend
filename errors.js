class AuthError extends Error {
  constructor(message) {
    super(message);
    this.name = "AuthError";
    this.message = `Authentication Error: ${message}`;
    this.code = 401;
  }
}

class BadRequest extends Error {
  constructor(message) {
    super(message);
    this.name = "BadRequest";
    if (!message) this.message = "Bad Request Error: check the API doc";
    this.code = 400;
  }
}

class DbError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DbError';
    this.message = "Error - DB error: Contact API owners for more info.";
    this.code = 500;
  }
}

class NotFoundError extends Error {
  constructor(message) {
    super(message);
    this.name = "NotFoundError";
    this.message = "Error - Pokemon was not found: check your request";
    this.code = 400;
  }
}

module.exports = {
  AuthError,
  BadRequest,
  DbError,
  NotFoundError,
};
