const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const z = require('zod');
const pino = require('pino');

// Configuration
const config = {
  PORT: process.env.PORT || 8001,
  JWT_SECRET: process.env.JWT_SECRET || 'your-secret-key-change-in-production',
  LOG_LEVEL: process.env.LOG_LEVEL || 'info'
};

// Logger setup
const logger = pino({
  level: config.LOG_LEVEL,
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'SYS:standard',
      ignore: 'pid,hostname'
    }
  }
});

// In-memory database
const usersDb = {};

// Validation schemas
const UserValidation = {
  register: z.object({
    email: z.string().email('Invalid email format'),
    password: z.string().min(6, 'Password must be at least 6 characters'),
    name: z.string().min(2, 'Name must be at least 2 characters')
  }),
  
  login: z.object({
    email: z.string().email('Invalid email format'),
    password: z.string().min(1, 'Password is required')
  }),
  
  updateProfile: z.object({
    name: z.string().min(2).optional(),
    email: z.string().email().optional()
  })
};

// Utility functions
const UserService = {
  async createUser(userData) {
    const userId = uuidv4();
    const now = new Date().toISOString();
    
    const user = {
      id: userId,
      email: userData.email,
      passwordHash: await bcrypt.hash(userData.password, 10),
      name: userData.name,
      roles: ['user'],
      createdAt: now,
      updatedAt: now
    };
    
    usersDb[userId] = user;
    return user;
  },
  
  findUserByEmail(email) {
    return Object.values(usersDb).find(user => user.email === email);
  },
  
  findUserById(userId) {
    return usersDb[userId];
  },
  
  getAllUsers() {
    return Object.values(usersDb);
  },
  
  updateUser(userId, updates) {
    const user = usersDb[userId];
    if (!user) return null;
    
    const updatedUser = {
      ...user,
      ...updates,
      updatedAt: new Date().toISOString()
    };
    
    usersDb[userId] = updatedUser;
    return updatedUser;
  },
  
  sanitizeUser(user) {
    const { passwordHash, ...sanitized } = user;
    return sanitized;
  }
};

// Auth middleware
const AuthMiddleware = {
  authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader?.startsWith('Bearer ')) {
      logger.warn({ requestId: req.id }, 'Missing or invalid authorization header');
      return res.unauthorized('Authorization token required');
    }

    const token = authHeader.substring(7);
    
    try {
      const decoded = jwt.verify(token, config.JWT_SECRET);
      req.user = decoded;
      logger.info({ requestId: req.id, userId: decoded.userId }, 'User authenticated');
      next();
    } catch (error) {
      logger.error({ requestId: req.id, error: error.message }, 'Token verification failed');
      return res.unauthorized('Invalid or expired token');
    }
  },

  requireRole(...roles) {
    return (req, res, next) => {
      if (!req.user?.roles?.some(role => roles.includes(role))) {
        logger.warn({ 
          requestId: req.id, 
          userId: req.user?.userId, 
          requiredRoles: roles 
        }, 'Access denied');
        return res.forbidden('Insufficient permissions');
      }
      next();
    };
  }
};

// Response helpers
const ResponseHelper = {
  success(res, data, statusCode = 200) {
    res.status(statusCode).json({
      success: true,
      data
    });
  },
  
  error(res, code, message, statusCode = 400) {
    res.status(statusCode).json({
      success: false,
      error: { code, message }
    });
  },
  
  unauthorized(res, message = 'Authorization token required') {
    this.error(res, 'UNAUTHORIZED', message, 401);
  },
  
  forbidden(res, message = 'Insufficient permissions') {
    this.error(res, 'FORBIDDEN', message, 403);
  },
  
  notFound(res, message = 'Resource not found') {
    this.error(res, 'NOT_FOUND', message, 404);
  },
  
  validationError(res, message) {
    this.error(res, 'VALIDATION_ERROR', message);
  },
  
  internalError(res, message = 'Internal server error') {
    this.error(res, 'INTERNAL_ERROR', message, 500);
  }
};

// Initialize Express app
const app = express();

// Add response helpers to res object
app.use((req, res, next) => {
  res.success = (data, statusCode) => ResponseHelper.success(res, data, statusCode);
  res.error = (code, message, statusCode) => ResponseHelper.error(res, code, message, statusCode);
  res.unauthorized = (message) => ResponseHelper.unauthorized(res, message);
  res.forbidden = (message) => ResponseHelper.forbidden(res, message);
  res.notFound = (message) => ResponseHelper.notFound(res, message);
  res.validationError = (message) => ResponseHelper.validationError(res, message);
  res.internalError = (message) => ResponseHelper.internalError(res, message);
  next();
});

// Middleware
app.use(cors());
app.use(express.json());

// Request ID middleware
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.id);
  logger.info({ requestId: req.id, method: req.method, url: req.url }, 'Incoming request');
  next();
});

// Route handlers
const AuthController = {
  async register(req, res) {
    try {
      const validation = UserValidation.register.safeParse(req.body);
      if (!validation.success) {
        logger.warn({ requestId: req.id, errors: validation.error.errors }, 'Validation failed');
        return res.validationError(validation.error.errors[0].message);
      }

      const { email, password, name } = validation.data;

      // Check if user exists
      if (UserService.findUserByEmail(email)) {
        logger.warn({ requestId: req.id, email }, 'User already exists');
        return res.error('USER_EXISTS', 'User with this email already exists');
      }

      // Create user
      const newUser = await UserService.createUser({ email, password, name });
      logger.info({ requestId: req.id, userId: newUser.id }, 'User registered successfully');

      res.success(UserService.sanitizeUser(newUser), 201);
    } catch (error) {
      logger.error({ requestId: req.id, error: error.message }, 'Registration error');
      res.internalError();
    }
  },

  async login(req, res) {
    try {
      const validation = UserValidation.login.safeParse(req.body);
      if (!validation.success) {
        return res.validationError(validation.error.errors[0].message);
      }

      const { email, password } = validation.data;
      const user = UserService.findUserByEmail(email);
      
      if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        logger.warn({ requestId: req.id, email }, 'Invalid credentials');
        return res.error('INVALID_CREDENTIALS', 'Invalid email or password', 401);
      }

      const token = jwt.sign(
        { userId: user.id, email: user.email, roles: user.roles },
        config.JWT_SECRET,
        { expiresIn: '24h' }
      );

      logger.info({ requestId: req.id, userId: user.id }, 'User logged in');

      res.success({
        token,
        user: UserService.sanitizeUser(user)
      });
    } catch (error) {
      logger.error({ requestId: req.id, error: error.message }, 'Login error');
      res.internalError();
    }
  }
};

const UserController = {
  getProfile(req, res) {
    const user = UserService.findUserById(req.user.userId);
    
    if (!user) {
      return res.notFound('User not found');
    }

    logger.info({ requestId: req.id, userId: user.id }, 'Profile retrieved');
    res.success(UserService.sanitizeUser(user));
  },

  async updateProfile(req, res) {
    try {
      const validation = UserValidation.updateProfile.safeParse(req.body);
      if (!validation.success) {
        return res.validationError(validation.error.errors[0].message);
      }

      const user = UserService.findUserById(req.user.userId);
      if (!user) {
        return res.notFound('User not found');
      }

      // Check if email is being changed and if it's already taken
      if (validation.data.email && validation.data.email !== user.email) {
        const existingUser = UserService.findUserByEmail(validation.data.email);
        if (existingUser) {
          return res.error('EMAIL_TAKEN', 'Email already in use');
        }
      }

      const updatedUser = UserService.updateUser(req.user.userId, validation.data);
      logger.info({ requestId: req.id, userId: user.id }, 'Profile updated');

      res.success(UserService.sanitizeUser(updatedUser));
    } catch (error) {
      logger.error({ requestId: req.id, error: error.message }, 'Profile update error');
      res.internalError();
    }
  },

  listUsers(req, res) {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const role = req.query.role;

    let users = UserService.getAllUsers().map(user => UserService.sanitizeUser(user));

    // Filter by role
    if (role) {
      users = users.filter(user => user.roles.includes(role));
    }

    // Pagination
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;
    const paginatedUsers = users.slice(startIndex, endIndex);

    logger.info({ 
      requestId: req.id, 
      page, 
      limit, 
      total: users.length 
    }, 'Users list retrieved');

    res.success({
      users: paginatedUsers,
      pagination: {
        page,
        limit,
        total: users.length,
        totalPages: Math.ceil(users.length / limit)
      }
    });
  },

  getUserById(req, res) {
    const user = UserService.findUserById(req.params.userId);
    
    if (!user) {
      return res.notFound('User not found');
    }

    res.success(UserService.sanitizeUser(user));
  }
};

// Routes
app.post('/api/v1/auth/register', AuthController.register);
app.post('/api/v1/auth/login', AuthController.login);

app.get('/api/v1/users/profile', AuthMiddleware.authenticate, UserController.getProfile);
app.put('/api/v1/users/profile', AuthMiddleware.authenticate, UserController.updateProfile);

app.get('/api/v1/users', 
  AuthMiddleware.authenticate, 
  AuthMiddleware.requireRole('admin'), 
  UserController.listUsers
);

app.get('/api/v1/users/:userId', UserController.getUserById);

// Health check
app.get('/health', (req, res) => {
  res.success({
    status: 'healthy',
    service: 'users-service',
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  logger.error({ requestId: req.id, error: error.message }, 'Unhandled error');
  res.internalError();
});

// 404 handler
app.use('*', (req, res) => {
  res.notFound('Route not found');
});

// Initialize server
async function initializeServer() {
  // Create admin user for testing
  const adminId = uuidv4();
  const now = new Date().toISOString();
  
  usersDb[adminId] = {
    id: adminId,
    email: 'admin@example.com',
    passwordHash: await bcrypt.hash('admin123', 10),
    name: 'Admin User',
    roles: ['admin', 'user'],
    createdAt: now,
    updatedAt: now
  };
  
  logger.info('Admin user created: admin@example.com / admin123');
  
  // Start server
  app.listen(config.PORT, '0.0.0.0', () => {
    logger.info({ port: config.PORT }, 'Users service started successfully');
  });
}

// Start the application
initializeServer().catch(error => {
  logger.error({ error: error.message }, 'Failed to initialize server');
  process.exit(1);
});