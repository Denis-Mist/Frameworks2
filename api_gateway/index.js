const express = require('express');
const cors = require('cors');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const pino = require('pino');

class ApiGateway {
  constructor() {
    this.app = express();
    this.port = process.env.PORT || 8000;
    this.jwtSecret = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
    
    this.services = {
      users: process.env.USERS_SERVICE_URL || 'http://service_users:8001',
      orders: process.env.ORDERS_SERVICE_URL || 'http://service_orders:8002'
    };

    this.logger = this.setupLogger();
    this.initializeMiddleware();
    this.setupRoutes();
    this.setupErrorHandling();
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

  initializeMiddleware() {
    // CORS Configuration
    this.app.use(cors({
      origin: '*',
      credentials: false,
      exposedHeaders: ['X-Request-ID'],
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'Accept']
    }));

    this.app.use(express.json());
    this.app.use(this.requestIdMiddleware.bind(this));
    this.app.use(this.rateLimiting());
  }

  requestIdMiddleware(req, res, next) {
    req.id = req.headers['x-request-id'] || uuidv4();
    res.setHeader('X-Request-ID', req.id);
    
    this.logger.info({ 
      requestId: req.id, 
      method: req.method, 
      url: req.url,
      ip: req.ip 
    }, 'Incoming request');
    
    next();
  }

  rateLimiting() {
    const generalLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 100,
      message: {
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests, please try again later'
        }
      },
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        this.logger.warn({ requestId: req.id, ip: req.ip }, 'Rate limit exceeded');
        res.status(429).json({
          success: false,
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many requests, please try again later'
          }
        });
      }
    });

    return generalLimiter;
  }

  createAuthLimiter() {
    return rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 5,
      message: {
        success: false,
        error: {
          code: 'AUTH_RATE_LIMIT_EXCEEDED',
          message: 'Too many authentication attempts, please try again later'
        }
      }
    });
  }

  verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader?.startsWith('Bearer ')) {
      this.logger.warn({ requestId: req.id }, 'Missing or invalid authorization header');
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authorization token required'
        }
      });
    }

    const token = authHeader.substring(7);
    
    try {
      const decoded = jwt.verify(token, this.jwtSecret);
      req.user = decoded;
      this.logger.info({ requestId: req.id, userId: decoded.userId }, 'Token verified successfully');
      next();
    } catch (error) {
      this.logger.error({ requestId: req.id, error: error.message }, 'Token verification failed');
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired token'
        }
      });
    }
  }

  async proxyRequest(service, req) {
    const serviceUrl = this.services[service];
    
    try {
      const headers = {
        'Content-Type': 'application/json',
        'X-Request-ID': req.id
      };

      if (req.headers.authorization) {
        headers.Authorization = req.headers.authorization;
      }

      const config = {
        method: req.method,
        url: `${serviceUrl}${req.path}`,
        headers,
        params: req.query,
        timeout: 5000,
        ...(req.body && { data: req.body })
      };

      this.logger.info({ 
        requestId: req.id, 
        targetUrl: config.url,
        method: req.method,
        service 
      }, 'Proxying request to service');

      const response = await axios(config);
      return response;
    } catch (error) {
      this.logger.error({ 
        requestId: req.id, 
        error: error.message,
        service 
      }, 'Service request failed');
      
      return error.response || null;
    }
  }

  createRouteHandler(service, requireAuth = false) {
    return async (req, res) => {
      try {
        if (requireAuth) {
          await new Promise((resolve, reject) => {
            this.verifyToken(req, res, (err) => {
              err ? reject(err) : resolve();
            });
          });
        }

        const response = await this.proxyRequest(service, req);
        
        if (!response) {
          return res.status(503).json({
            success: false,
            error: {
              code: 'SERVICE_UNAVAILABLE',
              message: `${service} service is temporarily unavailable`
            }
          });
        }

        res.status(response.status).json(response.data);
      } catch (error) {
        if (error.status === 401) {
          return; // Response already sent by verifyToken
        }
        
        this.logger.error({ requestId: req.id, error: error.message }, 'Route handler error');
        res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: `${service} service is temporarily unavailable`
          }
        });
      }
    };
  }

  setupRoutes() {
    const authLimiter = this.createAuthLimiter();

    // Authentication routes
    this.app.post('/api/v1/auth/register', authLimiter, this.createRouteHandler('users', false));
    this.app.post('/api/v1/auth/login', authLimiter, this.createRouteHandler('users', false));

    // User routes
    this.app.get('/api/v1/users/profile', this.createRouteHandler('users', true));
    this.app.put('/api/v1/users/profile', this.createRouteHandler('users', true));
    this.app.get('/api/v1/users', this.createRouteHandler('users', true));

    // Order routes
    this.app.post('/api/v1/orders', this.createRouteHandler('orders', true));
    this.app.get('/api/v1/orders/:orderId', this.createRouteHandler('orders', true));
    this.app.get('/api/v1/orders', this.createRouteHandler('orders', true));
    this.app.put('/api/v1/orders/:orderId/status', this.createRouteHandler('orders', true));
    this.app.delete('/api/v1/orders/:orderId', this.createRouteHandler('orders', true));

    // Health check
    this.app.get('/health', this.healthCheck.bind(this));

    // 404 handler
    this.app.use(this.notFoundHandler.bind(this));
  }

  async healthCheck(req, res) {
    const healthStatus = {
      gateway: 'healthy',
      users: 'unknown',
      orders: 'unknown',
      timestamp: new Date().toISOString()
    };

    try {
      await axios.get(`${this.services.users}/health`, { timeout: 2000 });
      healthStatus.users = 'healthy';
    } catch (error) {
      healthStatus.users = 'unhealthy';
      this.logger.error({ error: error.message }, 'Users service health check failed');
    }

    try {
      await axios.get(`${this.services.orders}/health`, { timeout: 2000 });
      healthStatus.orders = 'healthy';
    } catch (error) {
      healthStatus.orders = 'unhealthy';
      this.logger.error({ error: error.message }, 'Orders service health check failed');
    }

    const isHealthy = healthStatus.users === 'healthy' && healthStatus.orders === 'healthy';
    const statusCode = isHealthy ? 200 : 503;

    res.status(statusCode).json({
      success: isHealthy,
      data: {
        status: isHealthy ? 'healthy' : 'degraded',
        services: healthStatus
      }
    });
  }

  notFoundHandler(req, res) {
    this.logger.warn({ requestId: req.id, url: req.url }, 'Route not found');
    res.status(404).json({
      success: false,
      error: {
        code: 'NOT_FOUND',
        message: 'Route not found'
      }
    });
  }

  setupErrorHandling() {
    this.app.use((err, req, res, next) => {
      this.logger.error({ 
        requestId: req.id, 
        error: err.message, 
        stack: err.stack 
      }, 'Unhandled error occurred');
      
      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Internal server error'
        }
      });
    });
  }

  start() {
    this.app.listen(this.port, () => {
      this.logger.info({ port: this.port }, 'API Gateway server started successfully');
    });
  }
}

// Create and start the gateway
const apiGateway = new ApiGateway();
apiGateway.start();

module.exports = ApiGateway;