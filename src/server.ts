import * as bodyParser from 'body-parser';
import { create, defaults, router as jsonRouter } from 'json-server';
import * as jwt from 'jsonwebtoken';
import { JsonWebTokenError } from 'jsonwebtoken';
import { join } from 'path';

const PORT = process.env.PORT ?? 3000;
const DATA_PATH =
    process.env.DATA_PATH ?? __dirname.slice(process.cwd().length + 1);
const DATA_NAME = process.env.DATA_NAME ?? 'api.db.json';
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY ?? 'SecretKey';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN ?? '1h';

const server = create();

const router = jsonRouter(join(DATA_PATH, DATA_NAME));
const middlewares = defaults();

server.use(bodyParser.urlencoded({extended: true}));
server.use(bodyParser.json());
server.use(middlewares);

server.post('/api/login/token', (req, res) => {
    const payload: {
        username: string;
        password: string;
        grant_type: string;
        refresh_token: string;
    } = {
        username: req.body.username,
        password: req.body.password,
        refresh_token: req.body.refresh_token,
        grant_type: req.body.grant_type
    };
    switch (payload.grant_type) {
        case 'password': {
            const user: { id: number; username: string; password: string } | null =
                (router.db.get('users') as any)
                    .find({username: payload.username, password: payload.password})
                    .value() ?? null;

            if (user) {
                res.status(200).cookie('session', 'xxxxx', {
                    httpOnly: true,
                    path: '/api/login'
                }).json(TokensGenerator(user.username));
            } else {
                const status = 401;
                const message = 'Incorrect username or password';
                res.status(status).json({status, message});
            }
            break;
        }
        case 'refresh_token': {
            let object: string | jwt.JwtPayload;
            try {
                object = jwt.verify(payload.refresh_token, JWT_SECRET_KEY);
                res.status(200).json(TokensGenerator(object.sub));
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
        jwt.verify(payload.access_token, JWT_SECRET_KEY);
        res.status(200).json({status, message});
    } catch (err) {
        const status = 401;
        let message = 'Error verify access_token';

        if (err instanceof JsonWebTokenError) {
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
        jwt.verify(token, JWT_SECRET_KEY);
        next();
    } catch (err) {
        const status = 401;
        let message = 'Error verify access_token';

        if (err instanceof JsonWebTokenError) {
            message = err.message;
        }
        res.status(status).json({status, message});
    }
});
server.use(router);

server.listen(PORT, () => {
    console.log(`JSON Server is running on port: ${PORT}`);
});

function TokensGenerator(username: string | jwt.JwtPayload | undefined) {
    const access_token = jwt.sign({sub: username}, JWT_SECRET_KEY, {
        expiresIn: JWT_EXPIRES_IN
    });
    return {
        access_token,
        refresh_token: access_token,
        expires_in: JWT_EXPIRES_IN,
        token_type: 'bearer'
    };
}
