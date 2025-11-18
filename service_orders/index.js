const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const z = require('zod');
const pino = require('pino');
const axios = require('axios');
const EventEmitter = require('events');

class OrdersService {
  constructor() {
    this.app = express();
    this.port = process.env.PORT || 8002;
    this.jwtSecret = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
    this.usersServiceUrl = process.env.USERS_SERVICE_URL || 'http://service_users:8001';
    
    this.ordersDb = new Map();
    this.eventBus = new EventEmitter();
    this.logger = this.setupLogger();
    
    this.setupMiddleware();
    this.setupRoutes();
    this.setupEventHandlers();
  }

  setupLogger() {
    return pino({
      level: process.env.LOG_LEVEL || 'info',
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:standard',
          ignore: 'pid,hostname'
        }
      }
    });
  }

  setupEventHandlers() {
    this.eventBus.on('order.created', (order) => {
      this.logger.info({ orderId: order.id, userId: order.userId }, 'Domain Event: Order created');
    });

    this.eventBus.on('order.status.updated', (order) => {
      this.logger.info({ orderId: order.id, status: order.status }, 'Domain Event: Order status updated');
    });
  }

  setupMiddleware() {
    this.app.use(cors());
    this.app.use(express.json());
    this.app.use(this.requestIdMiddleware.bind(this));
  }

  requestIdMiddleware(req, res, next) {
    req.id = req.headers['x-request-id'] || uuidv4();
    res.setHeader('X-Request-ID', req.id);
    this.logger.info({ requestId: req.id, method: req.method, url: req.url }, 'Incoming request');
    next();
  }

  setupRoutes() {
    this.app.use('/api/v1/orders', this.createOrderRoutes());
    this.app.get('/health', this.healthCheck.bind(this));
  }

  createOrderRoutes() {
    const router = express.Router();
    
    router.use(this.authenticate.bind(this));
    
    router.post('/', this.createOrder.bind(this));
    router.get('/', this.getOrders.bind(this));
    router.get('/:orderId', this.getOrderById.bind(this));
    router.put('/:orderId/status', this.updateOrderStatus.bind(this));
    router.delete('/:orderId', this.cancelOrder.bind(this));
    
    return router;
  }

  // Validation Schemas
  get validationSchemas() {
    return {
      orderItem: z.object({
        product: z.string().min(1, 'Product name is required'),
        quantity: z.number().int().positive('Quantity must be positive')
      }),
      
      createOrder: z.object({
        userId: z.string().uuid('Invalid user ID format'),
        items: z.array(this.validationSchemas.orderItem).min(1, 'At least one item is required'),
        totalAmount: z.number().positive('Total amount must be positive')
      }),
      
      updateStatus: z.object({
        status: z.enum(['created', 'in_progress', 'completed', 'cancelled'], {
          errorMap: () => ({ message: 'Invalid status' })
        })
      })
    };
  }

  async authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader?.startsWith('Bearer ')) {
      this.logger.warn({ requestId: req.id }, 'Missing or invalid authorization header');
      return this.sendError(res, 401, 'UNAUTHORIZED', 'Authorization token required');
    }

    const token = authHeader.substring(7);
    
    try {
      const decoded = jwt.verify(token, this.jwtSecret);
      req.user = decoded;
      this.logger.info({ requestId: req.id, userId: decoded.userId }, 'User authenticated');
      next();
    } catch (error) {
      this.logger.error({ requestId: req.id, error: error.message }, 'Token verification failed');
      return this.sendError(res, 401, 'INVALID_TOKEN', 'Invalid or expired token');
    }
  }

  async checkUserExists(userId) {
    try {
      const response = await axios.get(`${this.usersServiceUrl}/api/v1/users/${userId}`);
      return response.data.success;
    } catch (error) {
      this.logger.error({ userId, error: error.message }, 'User existence check failed');
      return false;
    }
  }

  sendError(res, statusCode, errorCode, message) {
    return res.status(statusCode).json({
      success: false,
      error: { code: errorCode, message }
    });
  }

  sendSuccess(res, data, statusCode = 200) {
    return res.status(statusCode).json({
      success: true,
      data
    });
  }

  validateData(schema, data) {
    return schema.safeParse(data);
  }

  // Route Handlers
  async createOrder(req, res) {
    try {
      const validation = this.validateData(this.validationSchemas.createOrder, req.body);
      
      if (!validation.success) {
        this.logger.warn({ requestId: req.id, errors: validation.error.errors }, 'Validation failed');
        return this.sendError(res, 400, 'VALIDATION_ERROR', validation.error.errors[0].message);
      }

      const { userId, items, totalAmount } = validation.data;

      // Authorization check
      if (req.user.userId !== userId && !req.user.roles?.includes('admin')) {
        this.logger.warn({ requestId: req.id, userId, requesterId: req.user.userId }, 'Unauthorized order creation');
        return this.sendError(res, 403, 'FORBIDDEN', 'Cannot create order for another user');
      }

      // Verify user exists
      const userExists = await this.checkUserExists(userId);
      if (!userExists) {
        return this.sendError(res, 400, 'USER_NOT_FOUND', 'User does not exist');
      }

      const orderId = uuidv4();
      const timestamp = new Date().toISOString();
      
      const newOrder = {
        id: orderId,
        userId,
        items,
        status: 'created',
        totalAmount,
        createdAt: timestamp,
        updatedAt: timestamp
      };

      this.ordersDb.set(orderId, newOrder);
      this.logger.info({ requestId: req.id, orderId, userId }, 'Order created');

      // Emit domain event
      this.eventBus.emit('order.created', newOrder);

      return this.sendSuccess(res, newOrder, 201);
    } catch (error) {
      this.logger.error({ requestId: req.id, error: error.message }, 'Order creation error');
      return this.sendError(res, 500, 'INTERNAL_ERROR', 'Internal server error');
    }
  }

  getOrderById(req, res) {
    const order = this.ordersDb.get(req.params.orderId);
    
    if (!order) {
      return this.sendError(res, 404, 'ORDER_NOT_FOUND', 'Order not found');
    }

    // Authorization check
    if (order.userId !== req.user.userId && !req.user.roles?.includes('admin')) {
      this.logger.warn({ requestId: req.id, orderId: order.id, userId: req.user.userId }, 'Unauthorized order access');
      return this.sendError(res, 403, 'FORBIDDEN', 'Access denied');
    }

    this.logger.info({ requestId: req.id, orderId: order.id }, 'Order retrieved');
    return this.sendSuccess(res, order);
  }

  getOrders(req, res) {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
    const status = req.query.status;

    let orders = Array.from(this.ordersDb.values());

    // Filter by user (unless admin)
    if (!req.user.roles?.includes('admin')) {
      orders = orders.filter(order => order.userId === req.user.userId);
    }

    // Filter by status
    if (status) {
      orders = orders.filter(order => order.status === status);
    }

    // Sort orders
    orders.sort((a, b) => {
      if (a[sortBy] < b[sortBy]) return -sortOrder;
      if (a[sortBy] > b[sortBy]) return sortOrder;
      return 0;
    });

    // Pagination
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;
    const paginatedOrders = orders.slice(startIndex, endIndex);

    this.logger.info({ requestId: req.id, page, limit, total: orders.length }, 'Orders list retrieved');

    return this.sendSuccess(res, {
      orders: paginatedOrders,
      pagination: {
        page,
        limit,
        total: orders.length,
        totalPages: Math.ceil(orders.length / limit)
      }
    });
  }

  updateOrderStatus(req, res) {
    try {
      const validation = this.validateData(this.validationSchemas.updateStatus, req.body);
      
      if (!validation.success) {
        return this.sendError(res, 400, 'VALIDATION_ERROR', validation.error.errors[0].message);
      }

      const order = this.ordersDb.get(req.params.orderId);
      
      if (!order) {
        return this.sendError(res, 404, 'ORDER_NOT_FOUND', 'Order not found');
      }

      // Authorization check
      if (order.userId !== req.user.userId && !req.user.roles?.includes('admin')) {
        this.logger.warn({ requestId: req.id, orderId: order.id, userId: req.user.userId }, 'Unauthorized status update');
        return this.sendError(res, 403, 'FORBIDDEN', 'Access denied');
      }

      const updatedOrder = {
        ...order,
        status: validation.data.status,
        updatedAt: new Date().toISOString()
      };

      this.ordersDb.set(req.params.orderId, updatedOrder);
      this.logger.info({ requestId: req.id, orderId: order.id, newStatus: validation.data.status }, 'Order status updated');

      // Emit domain event
      this.eventBus.emit('order.status.updated', updatedOrder);

      return this.sendSuccess(res, updatedOrder);
    } catch (error) {
      this.logger.error({ requestId: req.id, error: error.message }, 'Status update error');
      return this.sendError(res, 500, 'INTERNAL_ERROR', 'Internal server error');
    }
  }

  cancelOrder(req, res) {
    const order = this.ordersDb.get(req.params.orderId);
    
    if (!order) {
      return this.sendError(res, 404, 'ORDER_NOT_FOUND', 'Order not found');
    }

    // Authorization check
    if (order.userId !== req.user.userId && !req.user.roles?.includes('admin')) {
      this.logger.warn({ requestId: req.id, orderId: order.id, userId: req.user.userId }, 'Unauthorized order cancellation');
      return this.sendError(res, 403, 'FORBIDDEN', 'Access denied');
    }

    // Cannot cancel completed orders
    if (order.status === 'completed') {
      return this.sendError(res, 400, 'CANNOT_CANCEL', 'Cannot cancel completed order');
    }

    const cancelledOrder = {
      ...order,
      status: 'cancelled',
      updatedAt: new Date().toISOString()
    };

    this.ordersDb.set(req.params.orderId, cancelledOrder);
    this.logger.info({ requestId: req.id, orderId: order.id }, 'Order cancelled');

    // Emit domain event
    this.eventBus.emit('order.status.updated', cancelledOrder);

    return this.sendSuccess(res, {
      message: 'Order cancelled',
      order: cancelledOrder
    });
  }

  healthCheck(req, res) {
    return this.sendSuccess(res, {
      status: 'healthy',
      service: 'orders-service',
      timestamp: new Date().toISOString(),
      totalOrders: this.ordersDb.size
    });
  }

  start() {
    this.app.listen(this.port, '0.0.0.0', () => {
      this.logger.info({ port: this.port }, 'Orders service started successfully');
    });
  }
}

// Create and start the service
const ordersService = new OrdersService();
ordersService.start();

module.exports = OrdersService;