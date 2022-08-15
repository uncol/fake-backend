import * as jwt from 'jsonwebtoken';
import { JWT } from '../config';

export function checkAuth() {
  return (req, res, next) => {
    if (
      req.headers.authorization === undefined ||
      req.headers.authorization.split(' ')[0] !== 'Bearer'
    ) {
      const status = 401;
      const message = 'Error in authorization format';
      res.status(status).json({ status, message });
      return;
    }
    try {
      const token = req.headers.authorization.split(' ')[1];
      jwt.verify(token, JWT.secret_key);
      next();
    } catch (err) {
      const status = 401;
      let message = 'Error verify access_token';

      if (err instanceof jwt.JsonWebTokenError) {
        message = err.message;
      }
      res.status(status).json({ status, message });
    }
  };
}
