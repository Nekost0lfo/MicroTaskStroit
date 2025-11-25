require('dotenv').config();
require('express-async-errors');

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const pino = require('pino');
const pinoHttp = require('pino-http');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { AsyncLocalStorage } = require('node:async_hooks');

const context = new AsyncLocalStorage();

const config = {
    port: Number(process.env.PORT) || 8000,
    env: process.env.NODE_ENV || 'development',
    jwtSecret: process.env.JWT_SECRET || 'shared-secret',
    usersServiceUrl: (process.env.USERS_SERVICE_URL || 'http://service_users:8100').replace(/\/$/, ''),
    ordersServiceUrl: (process.env.ORDERS_SERVICE_URL || 'http://service_orders:8200').replace(/\/$/, ''),
    logLevel: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
    rateLimitWindowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 60 * 1000,
    rateLimitMax: Number(process.env.RATE_LIMIT_MAX) || 120,
    slowDownAfter: Number(process.env.SLOW_DOWN_AFTER) || 40,
    slowDownDelayMs: Number(process.env.SLOW_DOWN_DELAY_MS) || 200
};

const logger = pino({
    level: config.logLevel,
    base: { service: 'api-gateway', env: config.env },
    timestamp: pino.stdTimeFunctions.isoTime
});

const app = express();

app.set('trust proxy', true);

const pinoMiddleware = pinoHttp({
    logger,
    genReqId: (req) => req.headers['x-request-id'] || uuidv4(),
    customLogLevel: (res, err) => {
        if (res.statusCode >= 500 || err) {
            return 'error';
        }
        if (res.statusCode >= 400) {
            return 'warn';
        }
        return 'info';
    }
});

app.use(pinoMiddleware);

app.use((req, res, next) => {
    const requestId = req.headers['x-request-id'] || req.id || uuidv4();
    req.id = requestId;
    res.setHeader('X-Request-ID', requestId);
    next();
});

app.use((req, res, next) => {
    const traceId = req.headers['x-trace-id'] || req.id || uuidv4();
    context.run({ traceId }, () => {
        req.traceId = traceId;
        req.log = req.log.child({ traceId, requestId: req.id });
        res.setHeader('X-Trace-Id', traceId);
        next();
    });
});

app.use(helmet());
app.use(cors({ exposedHeaders: ['X-Request-ID', 'X-Trace-Id'], maxAge: 600 }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const limiter = rateLimit({
    windowMs: config.rateLimitWindowMs,
    max: config.rateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            error: {
                code: 'rate_limit_exceeded',
                message: 'Too many requests, please slow down'
            }
        });
    }
});

const speedLimiter = slowDown({
    windowMs: config.rateLimitWindowMs,
    delayAfter: config.slowDownAfter,
    delayMs: config.slowDownDelayMs
});

app.use(limiter);
app.use(speedLimiter);

const httpError = (message, meta = {}) => {
    const err = new Error(message);
    err.status = meta.status || 500;
    err.code = meta.code || 'gateway_error';
    return err;
};

const getTraceId = () => context.getStore()?.traceId;

const requireJwt = (req, res, next) => {
    const header = req.headers.authorization;
    if (!header) {
        return next(httpError('Authorization required', { status: 401, code: 'auth_required' }));
    }
    const [scheme, token] = header.split(' ');
    if (scheme?.toLowerCase() !== 'bearer' || !token) {
        return next(httpError('Malformed authorization header', { status: 401, code: 'auth_malformed' }));
    }
    try {
        const payload = jwt.verify(token, config.jwtSecret);
        req.user = payload;
        next();
    } catch (error) {
        next(httpError('Invalid token', { status: 401, code: 'invalid_token' }));
    }
};

const userPathsWithoutAuth = new Set(['/register', '/login', '/status', '/health']);

const proxyRequest = (baseUrl) => async (req, res, next) => {
    try {
        const targetUrl = `${baseUrl}${req.originalUrl}`;
        const headers = {
            ...req.headers,
            host: new URL(baseUrl).host,
            'x-request-id': req.id,
            'x-trace-id': req.traceId
        };
        delete headers['content-length'];

        const response = await axios({
            url: targetUrl,
            method: req.method,
            headers,
            data: req.body,
            timeout: 10000,
            validateStatus: () => true
        });

        Object.entries(response.headers || {}).forEach(([key, value]) => {
            if (key.toLowerCase() === 'transfer-encoding') {
                return;
            }
            res.setHeader(key, value);
        });
        res.setHeader('X-Trace-Id', req.traceId);
        res.setHeader('X-Request-ID', req.id);
        res.status(response.status).send(response.data);
    } catch (error) {
        req.log.error({ err: error, traceId: req.traceId }, 'proxy failure');
        res.status(502).json({
            success: false,
            error: {
                code: error.code || 'bad_gateway',
                message: error.response?.data?.error?.message || 'Unable to reach downstream service'
            }
        });
    }
};

const usersRouter = express.Router();
usersRouter.use((req, res, next) => {
    if (userPathsWithoutAuth.has(req.path)) {
        return next();
    }
    return requireJwt(req, res, next);
});
usersRouter.use(proxyRequest(config.usersServiceUrl));

const ordersRouter = express.Router();
ordersRouter.use(requireJwt);
ordersRouter.use(proxyRequest(config.ordersServiceUrl));

app.use('/v1/users', usersRouter);
app.use('/v1/orders', ordersRouter);

app.get('/v1/health', (req, res) => {
    res.json({
        success: true,
        data: {
            status: 'Gateway is healthy',
            env: config.env,
            traceId: getTraceId()
        }
    });
});

app.get('/v1/status', (req, res) => {
    res.json({
        success: true,
        data: {
            status: 'Gateway is running',
            timestamp: new Date().toISOString()
        }
    });
});

app.use((req, res, next) => {
    next(httpError('Route not found', { status: 404, code: 'not_found' }));
});

app.use((err, req, res, next) => {
    const status = err.status || 500;
    const code = err.code || 'gateway_error';
    const message = err.message || 'Internal gateway error';
    req.log.error({ err, status, traceId: req.traceId }, 'gateway error');
    res.status(status).json({
        success: false,
        error: {
            code,
            message
        }
    });
});

app.listen(config.port, () => {
    logger.info({ port: config.port, env: config.env }, 'API Gateway listening');
});