require('dotenv').config();
require('express-async-errors');

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const pinoHttp = require('pino-http');
const { z } = require('zod');
const { v4: uuidv4 } = require('uuid');
const { AsyncLocalStorage } = require('node:async_hooks');

const context = new AsyncLocalStorage();

const config = {
    port: Number(process.env.PORT) || 8100,
    env: process.env.NODE_ENV || 'development',
    jwtSecret: process.env.JWT_SECRET || 'shared-secret',
    jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1h',
    logLevel: process.env.LOG_LEVEL || 'debug',
    systemToken: process.env.SERVICE_TOKEN || 'system-token',
    adminEmail: process.env.ADMIN_EMAIL || 'admin@example.com',
    adminPassword: process.env.ADMIN_PASSWORD || 'Admin123!'
};

const logger = pino({
    level: config.logLevel,
    base: { service: 'service-users', env: config.env },
    timestamp: pino.stdTimeFunctions.isoTime
});

const app = express();

app.set('trust proxy', true);

const pinoMiddleware = pinoHttp({
    logger,
    customLogLevel: (res, err) => {
        if (res.statusCode >= 500 || err) {
            return 'error';
        }
        if (res.statusCode >= 400) {
            return 'warn';
        }
        return 'info';
    },
    genReqId: (req) => req.headers['x-request-id'] || uuidv4()
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
        res.setHeader('X-Trace-Id', traceId);
        next();
    });
});

app.use(helmet());
app.use(cors({ exposedHeaders: ['X-Request-ID', 'X-Trace-Id'] }));
app.use(express.json());

const httpError = (message, meta = {}) => {
    const err = new Error(message);
    err.status = meta.status || 500;
    err.code = meta.code || 'server_error';
    return err;
};

const getTraceId = () => context.getStore()?.traceId;

const users = new Map();

const sanitizeUser = (user) => ({
    id: user.id,
    email: user.email,
    name: user.name,
    roles: user.roles,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
});

const buildToken = (user) => {
    return jwt.sign(
        {
            sub: user.id,
            email: user.email,
            roles: user.roles
        },
        config.jwtSecret,
        { expiresIn: config.jwtExpiresIn }
    );
};

const hashPassword = (password) => bcrypt.hash(password, 10);

const roleEnum = z.enum(['user', 'admin']);

const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
    name: z.string().min(1)
});

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(1)
});

const profileUpdateSchema = z.object({
    name: z.string().min(1).optional(),
    password: z.string().min(8).optional()
}).refine(
    (data) => Boolean(data.name) || Boolean(data.password),
    { message: 'name or password must be provided' }
);

const listUsersSchema = z.object({
    email: z.string().email().optional(),
    role: roleEnum.optional(),
    sort: z.enum(['createdAt', 'email', 'name']).default('createdAt'),
    order: z.enum(['asc', 'desc']).default('desc'),
    page: z.coerce.number().int().positive().default(1),
    perPage: z.coerce.number().int().positive().max(50).default(10)
});

const authRequired = (req, res, next) => {
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

const requireRole = (role) => (req, res, next) => {
    if (!req.user?.roles?.includes(role)) {
        return next(httpError('Insufficient permissions', { status: 403, code: 'insufficient_permissions' }));
    }
    next();
};

const parseBody = (schema) => (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
        return next(httpError(result.error.errors.map((err) => err.message).join('; '), { status: 400, code: 'validation_error' }));
    }
    req.validatedBody = result.data;
    next();
};

const parseQuery = (schema) => (req, res, next) => {
    const result = schema.safeParse(req.query);
    if (!result.success) {
        return next(httpError(result.error.errors.map((err) => err.message).join('; '), { status: 400, code: 'validation_error' }));
    }
    req.validatedQuery = result.data;
    next();
};

const registerUser = async ({ email, password, name, roles = ['user'] }) => {
    const now = new Date().toISOString();
    const passwordHash = await hashPassword(password);
    const user = {
        id: uuidv4(),
        email,
        name,
        roles,
        passwordHash,
        createdAt: now,
        updatedAt: now
    };
    users.set(user.id, user);
    return user;
};

const findUserByEmail = (email) => {
    return Array.from(users.values()).find((user) => user.email === email);
};

const ensureAdminSeeded = async () => {
    if (Array.from(users.values()).some((user) => user.roles.includes('admin'))) {
        return;
    }
    logger.info({ traceId: getTraceId() }, 'seeding admin user');
    await registerUser({
        email: config.adminEmail,
        password: config.adminPassword,
        name: 'Admin',
        roles: ['admin', 'user']
    });
};

const checkSystemToken = (req, res, next) => {
    const token = req.headers['x-system-token'];
    if (!token || token !== config.systemToken) {
        return next(httpError('Invalid internal token', { status: 401, code: 'invalid_system_token' }));
    }
    next();
};

app.get('/v1/health', (req, res) => {
    res.json({ success: true, data: { status: 'Users service healthy', env: config.env, traceId: getTraceId() } });
});

app.get('/v1/status', (req, res) => {
    res.json({ success: true, data: { status: 'Users service is running', timestamp: new Date().toISOString() } });
});

app.post('/v1/users/register', parseBody(registerSchema), async (req, res, next) => {
    const { email, password, name } = req.validatedBody;

    if (findUserByEmail(email)) {
        return next(httpError('Email already registered', { status: 409, code: 'email_taken' }));
    }

    const user = await registerUser({ email, password, name });
    req.log.info({ userId: user.id, traceId: req.traceId }, 'user registered');
    res.status(201).json({ success: true, data: { id: user.id, email: user.email } });
});

app.post('/v1/users/login', parseBody(loginSchema), async (req, res, next) => {
    const { email, password } = req.validatedBody;
    const user = findUserByEmail(email);

    if (!user) {
        return next(httpError('Invalid credentials', { status: 401, code: 'invalid_credentials' }));
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
        return next(httpError('Invalid credentials', { status: 401, code: 'invalid_credentials' }));
    }

    const token = buildToken(user);
    req.log.info({ userId: user.id, traceId: req.traceId }, 'user authenticated');
    res.json({
        success: true,
        data: {
            token,
            expiresIn: config.jwtExpiresIn
        }
    });
});

app.get('/v1/users/me', authRequired, (req, res) => {
    const user = users.get(req.user.sub);
    if (!user) {
        throw httpError('User not found', { status: 404, code: 'user_not_found' });
    }
    res.json({ success: true, data: sanitizeUser(user) });
});

app.put('/v1/users/me', authRequired, parseBody(profileUpdateSchema), async (req, res) => {
    const user = users.get(req.user.sub);
    if (!user) {
        throw httpError('User not found', { status: 404, code: 'user_not_found' });
    }
    const { name, password } = req.validatedBody;
    if (name) {
        user.name = name;
    }
    if (password) {
        user.passwordHash = await hashPassword(password);
    }
    user.updatedAt = new Date().toISOString();
    req.log.info({ userId: user.id, traceId: req.traceId }, 'user profile updated');
    res.json({ success: true, data: sanitizeUser(user) });
});

app.get('/v1/users', authRequired, requireRole('admin'), parseQuery(listUsersSchema), (req, res) => {
    const { email, role, sort, order, page, perPage } = req.validatedQuery;
    let list = Array.from(users.values());

    if (email) {
        list = list.filter((user) => user.email === email);
    }
    if (role) {
        list = list.filter((user) => user.roles.includes(role));
    }

    const comparators = {
        createdAt: (a, b) => new Date(a.createdAt) - new Date(b.createdAt),
        email: (a, b) => a.email.localeCompare(b.email),
        name: (a, b) => a.name.localeCompare(b.name)
    };
    list.sort((a, b) => (order === 'asc' ? 1 : -1) * comparators[sort](a, b));

    const total = list.length;
    const totalPages = Math.max(1, Math.ceil(total / perPage));
    const offset = (page - 1) * perPage;
    const items = list.slice(offset, offset + perPage).map(sanitizeUser);

    res.json({
        success: true,
        data: {
            items,
            page,
            perPage,
            total,
            totalPages
        }
    });
});

app.get('/v1/internal/users/:userId', checkSystemToken, (req, res, next) => {
    const user = users.get(req.params.userId);
    if (!user) {
        return next(httpError('User not found', { status: 404, code: 'user_not_found' }));
    }
    res.json({ success: true, data: { user: sanitizeUser(user) } });
});

app.use((req, res, next) => {
    next(httpError('Route not found', { status: 404, code: 'not_found' }));
});

app.use((err, req, res, next) => {
    const status = err.status || 500;
    const code = err.code || 'server_error';
    const message = err.message || 'Internal server error';
    req.log.error({ err, status, traceId: req.traceId }, 'request failed');
    res.status(status).json({
        success: false,
        error: {
            code,
            message
        }
    });
});

const start = async () => {
    await ensureAdminSeeded();
    app.listen(config.port, () => {
        logger.info({ port: config.port, env: config.env }, 'Users service listening');
    });
};

start();