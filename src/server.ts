import * as bodyParser from 'body-parser';
import * as cookieParser from  "cookie-parser";

import { create, defaults, router as jsonRouter } from 'json-server';
import * as jwt from 'jsonwebtoken';
import { join } from 'path';
import { v4 as uuidv4 } from 'uuid';

import { TokensGenerator } from './generator';

export interface config  {
    secret_key: string;
    access_token_expires_in: string;
    refresh_token_expires_in: number;
}

const PORT = process.env.PORT ?? 3000;
const DATA_PATH =
    process.env.DATA_PATH ?? __dirname.slice(process.cwd().length + 1);
const DATA_NAME = process.env.DATA_NAME ?? 'api.db.json';
const JWT: config = {
    secret_key: process.env.JWT_SECRET_KEY ?? 'SecretKey',
    access_token_expires_in: process.env.JWT_ACCESS_TOKEN_EXPIRES_IN ?? '1h',
    refresh_token_expires_in: Number(process.env.JWT_REFRESH_TOKEN_EXPIRES_IN ?? 2592000000), // 30 day
};
const COOKIE_NAME = 'refreshToken';

const server = create();

const router = jsonRouter(join(DATA_PATH, DATA_NAME));
const middlewares = defaults();

server.use(bodyParser.urlencoded({extended: true}));
server.use(bodyParser.json());
server.use(cookieParser.default());
server.use(middlewares);

server.post('/api/login/token', (req, res) => {
    const payload: {
        username: string;
        password: string;
        grant_type: string;
        refresh_token: string;
        visitorId: string;
    } = {
        username: req.body.username,
        password: req.body.password,
        refresh_token: req.body.refresh_token,
        grant_type: req.body.grant_type,
        visitorId: req.body.visitorId
    };

    switch (payload.grant_type) {
        case 'password': {
            const user: { id: number; username: string; password: string } | null =
                (router.db.get('users') as any)
                    .find({username: payload.username, password: payload.password})
                    .value() ?? null;

            if (user) {
                const newRefreshToken = uuidv4();
                // const oldRefreshToken = req.cookies[COOKIE_NAME];

                res.status(200).cookie(COOKIE_NAME, newRefreshToken, {
                    httpOnly: true,
                    path: '/api/login',
                    maxAge: JWT.refresh_token_expires_in,
                })
                .json(TokensGenerator(user.username, JWT));
            } else {
                const status = 401;
                const message = 'Incorrect username or password';
                res.status(status).json({status, message});
            }
            break;
        }
        case 'refresh_token': {
            const refresh_uuid = uuidv4();
            let object: string | jwt.JwtPayload;

            try {
                object = jwt.verify(payload.refresh_token, JWT.secret_key);
                res.status(200).cookie(COOKIE_NAME, refresh_uuid, {
                    httpOnly: true,
                    path: '/api/login',
                    maxAge: JWT.refresh_token_expires_in,
                }).json(TokensGenerator(object.sub, JWT));
            } catch (error) {
                const status = 401;
                const message = 'Error invalid access_token';
                res.status(status).json({status, message});
            }
            break;
        }
        default:
            break;
    }
});

server.post('/api/login/revoke', (req, res) => {
    res.status(200).json({message: 'Ok', status: true});
});

server.post('/api/login/is_login', (req, res) => {
    const status = 200;
    const message = 'Ok';
    const payload: {
        access_token: string;
    } = {
        access_token: req.body.access_token
    };
    try {
        jwt.verify(payload.access_token, JWT.secret_key);
        res.status(200).json({status, message});
    } catch (err) {
        const status = 401;
        let message = 'Error verify access_token';

        if (err instanceof jwt.JsonWebTokenError) {
            message = err.message;
        }
        res.status(status).json({status, message});
    }
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
    if (
        req.headers.authorization === undefined ||
        req.headers.authorization.split(' ')[0] !== 'Bearer'
    ) {
        const status = 401;
        const message = 'Error in authorization format';
        res.status(status).json({status, message});
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
        res.status(status).json({status, message});
    }
});
server.use(router);

server.listen(PORT, () => {
    console.log(`JSON Server is running on port: ${PORT}`);
});
