require('dotenv').config();
require('express-async-errors');

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const pinoHttp = require('pino-http');
const { z } = require('zod');
const { v4: uuidv4 } = require('uuid');
const { AsyncLocalStorage } = require('node:async_hooks');

const context = new AsyncLocalStorage();

const config = {
    port: Number(process.env.PORT) || 8200,
    env: process.env.NODE_ENV || 'development',
    jwtSecret: process.env.JWT_SECRET || 'shared-secret',
    logLevel: process.env.LOG_LEVEL || 'debug',
    userServiceUrl: process.env.USER_SERVICE_URL || 'http://service_users:8100/v1',
    systemToken: process.env.SYSTEM_API_TOKEN || 'system-token'
};

const logger = pino({
    level: config.logLevel,
    base: { service: 'service-orders', env: config.env },
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

const ORDER_STATUSES = ['created', 'in_progress', 'completed', 'cancelled'];

const orders = new Map();

const sanitizeOrder = (order) => ({
    id: order.id,
    userId: order.userId,
    items: order.items,
    status: order.status,
    total: order.total,
    createdAt: order.createdAt,
    updatedAt: order.updatedAt
});

class DomainEventBus {
    publish(event) {
        logger.info({ event, traceId: getTraceId() }, 'domain event published');
        // TODO: push to message broker in the next iteration
    }
}

const eventBus = new DomainEventBus();

const orderItemSchema = z.object({
    productId: z.string().min(1),
    name: z.string().min(1),
    quantity: z.coerce.number().int().positive(),
    unitPrice: z.coerce.number().positive()
});

const createOrderSchema = z.object({
    items: z.array(orderItemSchema).min(1)
});

const statusUpdateSchema = z.object({
    status: z.enum(ORDER_STATUSES)
});

const listSchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    perPage: z.coerce.number().int().positive().max(50).default(10),
    sort: z.enum(['createdAt', 'status']).default('createdAt'),
    order: z.enum(['asc', 'desc']).default('desc')
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

const requireAdmin = (req, res, next) => {
    if (!req.user?.roles?.includes('admin')) {
        return next(httpError('Admin scope required', { status: 403, code: 'admin_required' }));
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

const ensureUserExists = async (userId) => {
    try {
        const response = await axios.get(`${config.userServiceUrl}/internal/users/${userId}`, {
            headers: {
                'X-System-Token': config.systemToken
            },
            timeout: 5000
        });
        if (!response.data?.success) {
            throw httpError('User service rejected verification', { status: 502, code: 'user_service_error' });
        }
        return response.data.data.user;
    } catch (error) {
        if (error.response) {
            if (error.response.status === 404) {
                throw httpError('User not found while creating order', { status: 400, code: 'user_not_found' });
            }
            throw httpError('User service error', { status: 502, code: 'user_service_error' });
        }
        if (error.request) {
            throw httpError('User service unreachable', { status: 502, code: 'user_service_unreachable' });
        }
        throw error;
    }
};

app.get('/v1/health', (req, res) => {
    res.json({ success: true, data: { status: 'Orders service healthy', env: config.env, traceId: getTraceId() } });
});

app.get('/v1/status', (req, res) => {
    res.json({ success: true, data: { status: 'Orders service is running', timestamp: new Date().toISOString() } });
});

app.get('/v1/orders/status', (req, res) => {
    res.json({ success: true, data: { status: 'Orders gateway status', timestamp: new Date().toISOString() } });
});

app.get('/v1/orders/health', (req, res) => {
    res.json({ success: true, data: { service: 'orders', healthy: true, traceId: getTraceId() } });
});

app.post('/v1/orders', authRequired, parseBody(createOrderSchema), async (req, res, next) => {
    const userId = req.user.sub;
    await ensureUserExists(userId);
    const { items } = req.validatedBody;
    const now = new Date().toISOString();
    const total = items.reduce((acc, item) => acc + item.unitPrice * item.quantity, 0);
    const order = {
        id: uuidv4(),
        userId,
        items,
        status: 'created',
        total,
        createdAt: now,
        updatedAt: now
    };
    orders.set(order.id, order);
    eventBus.publish({ type: 'order.created', order: sanitizeOrder(order) });
    req.log.info({ orderId: order.id, traceId: req.traceId }, 'order created');
    res.status(201).json({ success: true, data: sanitizeOrder(order) });
});

app.get('/v1/orders', authRequired, parseQuery(listSchema), (req, res) => {
    const { page, perPage, sort, order } = req.validatedQuery;
    const userOrders = Array.from(orders.values()).filter((orderItem) => orderItem.userId === req.user.sub);

    const comparators = {
        createdAt: (a, b) => new Date(a.createdAt) - new Date(b.createdAt),
        status: (a, b) => a.status.localeCompare(b.status)
    };
    userOrders.sort((a, b) => (order === 'asc' ? 1 : -1) * comparators[sort](a, b));

    const total = userOrders.length;
    const totalPages = Math.max(1, Math.ceil(total / perPage));
    const offset = (page - 1) * perPage;
    const items = userOrders.slice(offset, offset + perPage).map(sanitizeOrder);

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

const findOrder = (orderId) => {
    const order = orders.get(orderId);
    if (!order) {
        throw httpError('Order not found', { status: 404, code: 'order_not_found' });
    }
    return order;
};

const ensureAccess = (req, order) => {
    if (req.user.sub !== order.userId && !req.user.roles?.includes('admin')) {
        throw httpError('Forbidden', { status: 403, code: 'forbidden' });
    }
};

app.get('/v1/orders/:orderId', authRequired, (req, res) => {
    const order = findOrder(req.params.orderId);
    ensureAccess(req, order);
    res.json({ success: true, data: sanitizeOrder(order) });
});

app.patch('/v1/orders/:orderId/status', authRequired, requireAdmin, parseBody(statusUpdateSchema), (req, res) => {
    const order = findOrder(req.params.orderId);
    const { status } = req.validatedBody;
    const previousStatus = order.status;
    order.status = status;
    order.updatedAt = new Date().toISOString();
    eventBus.publish({
        type: 'order.status.updated',
        orderId: order.id,
        userId: order.userId,
        previousStatus,
        status
    });
    req.log.info({ orderId: order.id, traceId: req.traceId, previousStatus, status }, 'order status updated');
    res.json({ success: true, data: sanitizeOrder(order) });
});

app.post('/v1/orders/:orderId/cancel', authRequired, (req, res) => {
    const order = findOrder(req.params.orderId);
    if (req.user.sub !== order.userId && !req.user.roles?.includes('admin')) {
        throw httpError('Only owner or admin can cancel', { status: 403, code: 'cancel_forbidden' });
    }
    if (order.status === 'cancelled') {
        return res.json({ success: true, data: sanitizeOrder(order) });
    }
    const previousStatus = order.status;
    order.status = 'cancelled';
    order.updatedAt = new Date().toISOString();
    eventBus.publish({
        type: 'order.status.updated',
        orderId: order.id,
        userId: order.userId,
        previousStatus,
        status: order.status
    });
    req.log.info({ orderId: order.id, traceId: req.traceId, previousStatus, status: order.status }, 'order cancelled');
    res.json({ success: true, data: sanitizeOrder(order) });
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

const start = () => {
    app.listen(config.port, () => {
        logger.info({ port: config.port, env: config.env }, 'Orders service listening');
    });
};

start();