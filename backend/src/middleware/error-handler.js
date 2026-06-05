const { ZodError } = require('zod');

function errorHandler(error, _req, res, _next) {
  if (error instanceof ZodError) {
    res.status(400).json({
      error: {
        message: 'Invalid request payload.',
        details: error.errors
      }
    });
    return;
  }

  const statusCode = error.statusCode || 500;
  const exposeMessage = statusCode < 500 || error.expose === true;

  if (statusCode >= 500) {
    console.error(error);
  }

  res.status(statusCode).json({
    error: {
      message: exposeMessage ? error.message : 'Internal server error'
    }
  });
}

module.exports = { errorHandler };
