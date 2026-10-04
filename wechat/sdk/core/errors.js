class SdkError extends Error {
  constructor(code, message, cause) {
    super(message);
    this.name = 'SdkError';
    this.code = code;
    if (cause !== undefined) {
      this.cause = cause;
    }
  }
}

class HttpError extends SdkError {
  constructor(statusCode, data) {
    super('HTTP_ERROR', `Request failed (HTTP ${statusCode})`);
    this.name = 'HttpError';
    this.statusCode = statusCode;
    this.data = data;
  }
}

module.exports = { SdkError, HttpError };
