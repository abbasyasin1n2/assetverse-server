require('dotenv').config();

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const { MongoClient, ServerApiVersion } = require('mongodb');
const Stripe = require('stripe');
const cloudinary = require('cloudinary').v2;

// Firebase admin credential: prefer base64 env for Vercel, fallback to local JSON
let firebaseServiceAccount;
if (process.env.FB_SERVICE_KEY) {
  try {
    const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8');
    firebaseServiceAccount = JSON.parse(decoded);
  } catch (err) {
    console.error('Failed to parse FB_SERVICE_KEY, falling back to local file:', err.message);
  }
}
if (!firebaseServiceAccount) {
  firebaseServiceAccount = require('./assestverse-clientside-firebase-adminsdk-serviceAccountKey.json');
}

admin.initializeApp({
  credential: admin.credential.cert(firebaseServiceAccount),
});

const stripe =
  process.env.STRIPE_SECRET_KEY && process.env.STRIPE_SECRET_KEY.trim()
    ? Stripe(process.env.STRIPE_SECRET_KEY)
    : null;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || '',
  api_key: process.env.CLOUDINARY_API_KEY || '',
  api_secret: process.env.CLOUDINARY_API_SECRET || '',
  secure: true,
});

const app = express();
const port = process.env.PORT || 5000;

// Support multiple origins for CORS (localhost + production Firebase URLs)
const allowedOrigins = process.env.CLIENT_ORIGIN
  ? process.env.CLIENT_ORIGIN.split(',')
  : ['http://localhost:5173'];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);
      
      if (allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
  })
);
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

const isProduction = process.env.NODE_ENV === 'production';
const cookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? 'none' : 'lax',
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: '/',
};

const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) {
    return res.status(401).send({ message: 'Unauthorized: missing token' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (error) {
    return res.status(401).send({ message: 'Unauthorized: invalid token' });
  }
};

const verifyHR = (req, res, next) => {
  if (req.user?.role !== 'hr') {
    return res.status(403).send({ message: 'Forbidden: HR only' });
  }
  return next();
};

const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    const db = client.db('assetverse');

    const usersCollection = db.collection('users');
    const assetsCollection = db.collection('assets');
    const requestsCollection = db.collection('requests');
    const assignedAssetsCollection = db.collection('assignedAssets');
    const employeeAffiliationsCollection = db.collection('employeeAffiliations');
    const packagesCollection = db.collection('packages');
    const paymentsCollection = db.collection('payments');

    // Ensure unique payment records to prevent duplicate inserts
    await paymentsCollection.createIndex({ stripeSessionId: 1 }, { unique: true }).catch(() => {});
    await paymentsCollection.createIndex({ stripePaymentIntentId: 1 }, { unique: true }).catch(() => {});

    // Comment out ping command for Vercel deployment (prevents gateway timeout)
    // await db.command({ ping: 1 });
    console.log('Connected to MongoDB and collections initialized');

    // Auth: exchange Firebase ID token for app JWT
    app.post('/jwt', async (req, res) => {
      const idToken = req.body?.token;
      if (!idToken) {
        return res.status(400).send({ message: 'Firebase ID token required' });
      }

      let decodedFirebase;
      try {
        decodedFirebase = await admin.auth().verifyIdToken(idToken);
      } catch (error) {
        return res.status(401).send({ message: 'Invalid Firebase token' });
      }

      const email = decodedFirebase?.email;
      if (!email) {
        return res.status(400).send({ message: 'Email not found in token' });
      }

      const dbUser = await usersCollection.findOne({ email });
      const role = dbUser?.role;
      if (!role) {
        return res
          .status(403)
          .send({ message: 'User role not found in database' });
      }

      const token = jwt.sign({ email, role }, process.env.JWT_SECRET, {
        expiresIn: '7d',
      });

      res.cookie('token', token, cookieOptions);
      return res.send({ success: true, role });
    });

    // Logout clears the auth cookie
    app.post('/logout', (req, res) => {
      res.clearCookie('token', {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? 'none' : 'lax',
        path: '/',
      });
      return res.send({ success: true });
    });

    // Example protected routes
    app.get('/protected', verifyToken, (req, res) => {
      return res.send({ message: 'Protected route OK', user: req.user });
    });

    app.get('/hr-only', verifyToken, verifyHR, (req, res) => {
      return res.send({ message: 'HR route OK', user: req.user });
    });

    // Placeholder configs for Stripe / Cloudinary usage
    app.get('/payments/config', (req, res) => {
      return res.send({
        stripeConfigured: Boolean(stripe),
        cloudinaryConfigured:
          Boolean(process.env.CLOUDINARY_CLOUD_NAME) &&
          Boolean(process.env.CLOUDINARY_API_KEY) &&
          Boolean(process.env.CLOUDINARY_API_SECRET),
      });
    });

    // ============ CLOUDINARY ROUTES ============

    // Initialize Cloudinary folder structure
    app.post('/cloudinary/init-folders', async (req, res) => {
      try {
        // Create placeholder files in each folder to ensure folders exist
        // Cloudinary creates folders automatically when you upload to them
        const folders = ['assetverse/assets', 'assetverse/companies', 'assetverse/employees'];
        
        const results = await Promise.all(
          folders.map(async (folder) => {
            try {
              // Check if folder exists by trying to list resources in it
              const existingResources = await cloudinary.api.resources({
                type: 'upload',
                prefix: folder,
                max_results: 1,
              });
              
              return { folder, status: 'exists', count: existingResources.resources.length };
            } catch (error) {
              // Folder might not exist yet, which is fine
              return { folder, status: 'ready_for_uploads', message: 'Folder will be created on first upload' };
            }
          })
        );

        return res.send({
          success: true,
          message: 'Cloudinary folder structure initialized',
          folders: results,
        });
      } catch (error) {
        console.error('Cloudinary init-folders error:', error);
        return res.status(500).send({ 
          success: false, 
          message: 'Failed to initialize folders',
          error: error.message 
        });
      }
    });

    // Generate upload signature for secure client-side uploads
    app.post('/cloudinary/signature', (req, res) => {
      try {
        const { folder } = req.body;
        
        // Validate folder - only allow uploads to approved folders
        const allowedFolders = [
          'assetverse/assets',
          'assetverse/companies',
          'assetverse/employees',
        ];
        if (!folder || !allowedFolders.includes(folder)) {
          return res.status(400).send({
            success: false,
            message: `Invalid folder. Allowed: ${allowedFolders.join(', ')}`,
          });
        }

        const timestamp = Math.round(new Date().getTime() / 1000);
        
        // Parameters to sign
        const paramsToSign = {
          timestamp,
          folder,
        };

        // Generate signature
        const signature = cloudinary.utils.api_sign_request(
          paramsToSign,
          process.env.CLOUDINARY_API_SECRET
        );

        return res.send({
          success: true,
          signature,
          timestamp,
          folder,
          cloudName: process.env.CLOUDINARY_CLOUD_NAME,
          apiKey: process.env.CLOUDINARY_API_KEY,
        });
      } catch (error) {
        console.error('Cloudinary signature error:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to generate signature',
          error: error.message,
        });
      }
    });

    // Direct upload endpoint (JSON with base64)
    app.post('/cloudinary/upload', async (req, res) => {
      try {
        const { file, folder } = req.body;
        
        if (!file) {
          return res.status(400).send({
            success: false,
            message: 'No file provided',
          });
        }

        const allowedFolders = [
          'assetverse/assets',
          'assetverse/companies',
          'assetverse/employees',
        ];
        
        const uploadFolder = folder && allowedFolders.includes(folder) 
          ? folder 
          : 'assetverse/assets';

        // Upload base64 image to Cloudinary
        const result = await cloudinary.uploader.upload(file, {
          folder: uploadFolder,
          resource_type: 'auto',
        });

        return res.send({
          success: true,
          message: 'Image uploaded successfully',
          url: result.secure_url,
          data: {
            publicId: result.public_id,
            url: result.secure_url,
            folder: result.folder,
            format: result.format,
            width: result.width,
            height: result.height,
          },
        });
      } catch (error) {
        console.error('Cloudinary upload error:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to upload image',
          error: error.message,
        });
      }
    });

    // Get Cloudinary config for client (safe to expose cloud name and api key)
    app.get('/cloudinary/config', (req, res) => {
      return res.send({
        cloudName: process.env.CLOUDINARY_CLOUD_NAME,
        apiKey: process.env.CLOUDINARY_API_KEY,
        folders: {
          assets: 'assetverse/assets',
          companies: 'assetverse/companies',
          employees: 'assetverse/employees',
        },
      });
    });

    // ============ USER ROUTES ============

    // Create/Register a new user
    app.post('/users', async (req, res) => {
      try {
        const userData = req.body;
        
        // Validate required fields
        if (!userData.email || !userData.name || !userData.role) {
          return res.status(400).send({ 
            success: false, 
            message: 'Missing required fields: email, name, role' 
          });
        }

        // Check if user already exists
        const existingUser = await usersCollection.findOne({ email: userData.email });
        if (existingUser) {
          return res.status(409).send({ 
            success: false, 
            message: 'User already exists with this email' 
          });
        }

        // Add timestamps if not provided
        const userToInsert = {
          ...userData,
          createdAt: userData.createdAt || new Date().toISOString(),
          updatedAt: userData.updatedAt || new Date().toISOString(),
        };

        const result = await usersCollection.insertOne(userToInsert);
        
        return res.status(201).send({
          success: true,
          message: 'User registered successfully',
          insertedId: result.insertedId,
        });
      } catch (error) {
        console.error('Error creating user:', error);
        return res.status(500).send({ 
          success: false, 
          message: 'Failed to create user',
          error: error.message 
        });
      }
    });

    // Get user by email
    app.get('/users/:email', async (req, res) => {
      try {
        const { email } = req.params;
        
        const user = await usersCollection.findOne({ email });
        
        if (!user) {
          return res.status(404).send({ 
            success: false, 
            message: 'User not found' 
          });
        }

        return res.send(user);
      } catch (error) {
        console.error('Error fetching user:', error);
        return res.status(500).send({ 
          success: false, 
          message: 'Failed to fetch user',
          error: error.message 
        });
      }
    });

    // Update user by email
    app.patch('/users/:email', async (req, res) => {
      try {
        const { email } = req.params;
        const updateData = req.body;

        // Don't allow email or role changes through this endpoint
        delete updateData.email;
        delete updateData.role;

        updateData.updatedAt = new Date().toISOString();

        // Get the user to check their role
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ 
            success: false, 
            message: 'User not found' 
          });
        }

        const result = await usersCollection.updateOne(
          { email },
          { $set: updateData }
        );

        // If HR updates their company name, sync it across related collections
        if (user.role === 'hr' && updateData.companyName) {
          // Update company name in all employee affiliations
          await employeeAffiliationsCollection.updateMany(
            { companyEmail: email },
            { $set: { companyName: updateData.companyName, updatedAt: new Date().toISOString() } }
          );

          // Update company name in all assets
          await assetsCollection.updateMany(
            { companyEmail: email },
            { $set: { companyName: updateData.companyName, updatedAt: new Date().toISOString() } }
          );

          // Update company name in all requests
          await requestsCollection.updateMany(
            { companyEmail: email },
            { $set: { companyName: updateData.companyName, updatedAt: new Date().toISOString() } }
          );
        }

        return res.send({
          success: true,
          message: 'User updated successfully',
          modifiedCount: result.modifiedCount,
        });
      } catch (error) {
        console.error('Error updating user:', error);
        return res.status(500).send({ 
          success: false, 
          message: 'Failed to update user',
          error: error.message 
        });
      }
    });

    // Check if email exists (for registration validation)
    app.get('/users/check/:email', async (req, res) => {
      try {
        const { email } = req.params;
        const user = await usersCollection.findOne({ email }, { projection: { _id: 1 } });
        
        return res.send({ exists: Boolean(user) });
      } catch (error) {
        console.error('Error checking email:', error);
        return res.status(500).send({ 
          success: false, 
          message: 'Failed to check email' 
        });
      }
    });

    // ============ PACKAGES ROUTES ============

    // Default packages data
    const defaultPackages = [
      {
        name: 'Basic',
        price: 0,
        currency: 'BDT',
        employeeLimit: 5,
        features: [
          'Up to 5 employees',
          'Basic asset tracking',
          'Email support',
          'Monthly reports',
        ],
        isPopular: false,
        stripePriceId: null,
      },
      {
        name: 'Standard',
        price: 8,
        currency: 'USD',
        employeeLimit: 10,
        features: [
          'Up to 10 employees',
          'Advanced asset tracking',
          'Priority email support',
          'Weekly reports',
          'Asset analytics',
        ],
        isPopular: true,
        stripePriceId: process.env.STRIPE_STANDARD_PRICE_ID || null,
      },
      {
        name: 'Premium',
        price: 15,
        currency: 'USD',
        employeeLimit: 20,
        features: [
          'Up to 20 employees',
          'Full asset management',
          '24/7 priority support',
          'Real-time reports',
          'Advanced analytics',
          'Custom integrations',
          'Dedicated account manager',
        ],
        isPopular: false,
        stripePriceId: process.env.STRIPE_PREMIUM_PRICE_ID || null,
      },
    ];

    // Get all packages
    app.get('/packages', async (req, res) => {
      try {
        const packages = await packagesCollection.find({}).toArray();
        
        // If no packages in DB, return default packages
        if (packages.length === 0) {
          return res.send(defaultPackages);
        }

        return res.send(packages);
      } catch (error) {
        console.error('Error fetching packages:', error);
        return res.status(500).send({ 
          success: false, 
          message: 'Failed to fetch packages',
          error: error.message 
        });
      }
    });

    // Get single package by ID
    app.get('/packages/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { ObjectId } = require('mongodb');
        
        const package_ = await packagesCollection.findOne({ 
          _id: new ObjectId(id) 
        });
        
        if (!package_) {
          return res.status(404).send({ 
            success: false, 
            message: 'Package not found' 
          });
        }

        return res.send(package_);
      } catch (error) {
        console.error('Error fetching package:', error);
        return res.status(500).send({ 
          success: false, 
          message: 'Failed to fetch package',
          error: error.message 
        });
      }
    });

    // Get package by name (for registration)
    app.get('/packages/name/:name', async (req, res) => {
      try {
        const { name } = req.params;
        
        // First try from DB
        let package_ = await packagesCollection.findOne({ 
          name: { $regex: new RegExp(`^${name}$`, 'i') }
        });
        
        // If not in DB, find from defaults
        if (!package_) {
          package_ = defaultPackages.find(
            p => p.name.toLowerCase() === name.toLowerCase()
          );
        }

        if (!package_) {
          return res.status(404).send({ 
            success: false, 
            message: 'Package not found' 
          });
        }

        return res.send(package_);
      } catch (error) {
        console.error('Error fetching package by name:', error);
        return res.status(500).send({ 
          success: false, 
          message: 'Failed to fetch package',
          error: error.message 
        });
      }
    });

    // ============ ASSETS ROUTES ============

    // Create a new asset (HR only)
    app.post('/assets', verifyToken, verifyHR, async (req, res) => {
      try {
        const assetData = req.body;
        const hrEmail = req.user.email;

        // Get HR's company info
        const hrUser = await usersCollection.findOne({ email: hrEmail });
        if (!hrUser) {
          return res.status(404).send({
            success: false,
            message: 'HR user not found',
          });
        }

        // Validate required fields
        if (!assetData.name || !assetData.type) {
          return res.status(400).send({
            success: false,
            message: 'Missing required fields: name, type',
          });
        }

        // Build asset document
        const assetToInsert = {
          ...assetData,
          companyEmail: hrEmail,
          companyName: hrUser.companyName,
          quantity: assetData.quantity || 1,
          availableQuantity: assetData.availableQuantity ?? assetData.quantity ?? 1,
          status: assetData.status || 'available',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };

        const result = await assetsCollection.insertOne(assetToInsert);

        return res.status(201).send({
          success: true,
          message: 'Asset created successfully',
          insertedId: result.insertedId,
        });
      } catch (error) {
        console.error('Error creating asset:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to create asset',
          error: error.message,
        });
      }
    });

    // Get all assets for HR's company (with search, filter, pagination)
    app.get('/assets', verifyToken, async (req, res) => {
      try {
        const { search, type, category, status, sort, page = 1, limit = 10 } = req.query;
        const userEmail = req.user.email;

        // Get user to check role
        const user = await usersCollection.findOne({ email: userEmail });

        // Build query based on role
        let query = {};
        
        if (user?.role === 'hr') {
          // HR sees their company's assets
          query.companyEmail = userEmail;
        } else {
          // Employee sees assets from companies they're affiliated with
          // For now, show all available assets (will refine with affiliations later)
          query.status = 'available';
        }

        // Search filter - use $and to combine with existing filters
        if (search) {
          query.$and = [
            { companyEmail: query.companyEmail },
            {
              $or: [
                { name: { $regex: search, $options: 'i' } },
                { category: { $regex: search, $options: 'i' } },
              ],
            },
          ];
          // Remove the separate companyEmail since it's now in $and
          if (user?.role === 'hr') {
            delete query.companyEmail;
          }
        }

        // Type filter (returnable/non-returnable)
        if (type && type !== 'all') {
          query.type = type;
        }

        // Category filter
        if (category && category !== 'All Categories') {
          query.category = category;
        }

        // Status filter
        if (status && status !== 'all') {
          query.status = status;
        }

        // Sorting
        let sortOption = { createdAt: -1 }; // Default: newest first
        if (sort === 'name-asc') sortOption = { name: 1 };
        if (sort === 'name-desc') sortOption = { name: -1 };
        if (sort === 'quantity-asc') sortOption = { quantity: 1 };
        if (sort === 'quantity-desc') sortOption = { quantity: -1 };

        // Pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const totalCount = await assetsCollection.countDocuments(query);

        const assets = await assetsCollection
          .find(query)
          .sort(sortOption)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        return res.send({
          success: true,
          data: assets,
          pagination: {
            total: totalCount,
            page: parseInt(page),
            limit: parseInt(limit),
            totalPages: Math.ceil(totalCount / parseInt(limit)),
          },
        });
      } catch (error) {
        console.error('Error fetching assets:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch assets',
          error: error.message,
        });
      }
    });

    // Get available assets for employees (Request Asset page)
    // IMPORTANT: This route MUST be before /assets/:id to avoid route collision
    app.get('/assets/available', verifyToken, async (req, res) => {
      try {
        const { search, type, category, page = 1, limit = 12 } = req.query;

        // Build query conditions
        const conditions = [];

        // Must have available quantity
        conditions.push({
          $or: [
            { availableQuantity: { $gt: 0 } },
            { quantity: { $gt: 0 }, availableQuantity: { $exists: false } },
          ],
        });

        // Type filter
        if (type) {
          conditions.push({ type: type });
        }

        // Category filter
        if (category) {
          conditions.push({ category: category });
        }

        // Search filter
        if (search) {
          conditions.push({ name: { $regex: search, $options: 'i' } });
        }

        const query = conditions.length > 0 ? { $and: conditions } : {};

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const totalCount = await assetsCollection.countDocuments(query);

        const assets = await assetsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        return res.send({
          success: true,
          data: assets,
          pagination: {
            total: totalCount,
            page: parseInt(page),
            limit: parseInt(limit),
            totalPages: Math.ceil(totalCount / parseInt(limit)),
          },
        });
      } catch (error) {
        console.error('Error fetching available assets:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch assets',
          error: error.message,
        });
      }
    });

    // Get single asset by ID
    app.get('/assets/:id', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const { ObjectId } = require('mongodb');

        // Validate ObjectId format (24 hex characters)
        if (!id || !/^[0-9a-fA-F]{24}$/.test(id)) {
          return res.status(400).send({
            success: false,
            message: 'Invalid asset ID format',
          });
        }

        const asset = await assetsCollection.findOne({ _id: new ObjectId(id) });

        if (!asset) {
          return res.status(404).send({
            success: false,
            message: 'Asset not found',
          });
        }

        return res.send(asset);
      } catch (error) {
        console.error('Error fetching asset:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch asset',
          error: error.message,
        });
      }
    });

    // Update asset (HR only)
    app.patch('/assets/:id', verifyToken, verifyHR, async (req, res) => {
      try {
        const { id } = req.params;
        const updateData = req.body;
        const hrEmail = req.user.email;
        const { ObjectId } = require('mongodb');

        // Verify the asset belongs to this HR's company
        const existingAsset = await assetsCollection.findOne({
          _id: new ObjectId(id),
          companyEmail: hrEmail,
        });

        if (!existingAsset) {
          return res.status(404).send({
            success: false,
            message: 'Asset not found or unauthorized',
          });
        }

        // Don't allow changing company info
        delete updateData.companyEmail;
        delete updateData.companyName;
        delete updateData._id;

        updateData.updatedAt = new Date().toISOString();

        const result = await assetsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );

        return res.send({
          success: true,
          message: 'Asset updated successfully',
          modifiedCount: result.modifiedCount,
        });
      } catch (error) {
        console.error('Error updating asset:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to update asset',
          error: error.message,
        });
      }
    });

    // Delete asset (HR only)
    app.delete('/assets/:id', verifyToken, verifyHR, async (req, res) => {
      try {
        const { id } = req.params;
        const hrEmail = req.user.email;
        const { ObjectId } = require('mongodb');

        // Verify the asset belongs to this HR's company
        const result = await assetsCollection.deleteOne({
          _id: new ObjectId(id),
          companyEmail: hrEmail,
        });

        if (result.deletedCount === 0) {
          return res.status(404).send({
            success: false,
            message: 'Asset not found or unauthorized',
          });
        }

        return res.send({
          success: true,
          message: 'Asset deleted successfully',
        });
      } catch (error) {
        console.error('Error deleting asset:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to delete asset',
          error: error.message,
        });
      }
    });

    // Get asset statistics for HR dashboard
    app.get('/assets/stats/summary', verifyToken, verifyHR, async (req, res) => {
      try {
        const hrEmail = req.user.email;

        const stats = await assetsCollection.aggregate([
          { $match: { companyEmail: hrEmail } },
          {
            $group: {
              _id: null,
              totalAssets: { $sum: 1 },
              totalQuantity: { $sum: '$quantity' },
              availableQuantity: { $sum: '$availableQuantity' },
              returnableCount: {
                $sum: { $cond: [{ $eq: ['$type', 'returnable'] }, 1, 0] },
              },
              nonReturnableCount: {
                $sum: { $cond: [{ $eq: ['$type', 'non-returnable'] }, 1, 0] },
              },
            },
          },
        ]).toArray();

        // Get assets by category
        const byCategory = await assetsCollection.aggregate([
          { $match: { companyEmail: hrEmail } },
          {
            $group: {
              _id: '$category',
              count: { $sum: 1 },
              totalQuantity: { $sum: '$quantity' },
            },
          },
          { $sort: { count: -1 } },
        ]).toArray();

        return res.send({
          success: true,
          summary: stats[0] || {
            totalAssets: 0,
            totalQuantity: 0,
            availableQuantity: 0,
            returnableCount: 0,
            nonReturnableCount: 0,
          },
          byCategory,
        });
      } catch (error) {
        console.error('Error fetching asset stats:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch asset statistics',
          error: error.message,
        });
      }
    });

    // ============ REQUESTS ROUTES ============

    // Create asset request (Employee)
    app.post('/requests', verifyToken, async (req, res) => {
      try {
        const { assetId, notes, message, urgency } = req.body;
        const requestMessage = message || notes || '';
        const employeeEmail = req.user.email;
        const { ObjectId } = require('mongodb');

        // Get employee info
        const employee = await usersCollection.findOne({ email: employeeEmail });
        if (!employee || employee.role !== 'employee') {
          return res.status(403).send({
            success: false,
            message: 'Only employees can request assets',
          });
        }

        // Get asset info
        const asset = await assetsCollection.findOne({ _id: new ObjectId(assetId) });
        if (!asset) {
          return res.status(404).send({
            success: false,
            message: 'Asset not found',
          });
        }

        // Check if asset is available
        if (asset.availableQuantity < 1) {
          return res.status(400).send({
            success: false,
            message: 'Asset is not available',
          });
        }

        // Check for duplicate pending request
        const existingRequest = await requestsCollection.findOne({
          assetId: new ObjectId(assetId),
          employeeEmail,
          status: 'pending',
        });

        if (existingRequest) {
          return res.status(400).send({
            success: false,
            message: 'You already have a pending request for this asset',
          });
        }

        // Create request
        const requestDoc = {
          assetId: new ObjectId(assetId),
          assetName: asset.name,
          assetType: asset.type,
          assetImage: asset.image,
          employeeEmail,
          employeeName: employee.name,
          companyEmail: asset.companyEmail,
          companyName: asset.companyName,
          message: requestMessage,
          notes: requestMessage,
          urgency: urgency || 'normal',
          status: 'pending',
          requestDate: new Date().toISOString(),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };

        const result = await requestsCollection.insertOne(requestDoc);

        return res.status(201).send({
          success: true,
          message: 'Request submitted successfully',
          insertedId: result.insertedId,
        });
      } catch (error) {
        console.error('Error creating request:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to create request',
          error: error.message,
        });
      }
    });

    // Get requests (role-based: HR sees company requests, Employee sees own)
    app.get('/requests', verifyToken, async (req, res) => {
      try {
        const { status, search, page = 1, limit = 10 } = req.query;
        const userEmail = req.user.email;
        const user = await usersCollection.findOne({ email: userEmail });

        let query = {};

        if (user?.role === 'hr') {
          // HR sees requests for their company's assets
          query.companyEmail = userEmail;
        } else {
          // Employee sees their own requests
          query.employeeEmail = userEmail;
        }

        // Status filter
        if (status && status !== 'all') {
          query.status = status;
        }

        // Search filter
        if (search) {
          query.$or = [
            { assetName: { $regex: search, $options: 'i' } },
            { employeeName: { $regex: search, $options: 'i' } },
          ];
        }

        // Pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const totalCount = await requestsCollection.countDocuments(query);

        const requests = await requestsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        return res.send({
          success: true,
          data: requests,
          pagination: {
            total: totalCount,
            page: parseInt(page),
            limit: parseInt(limit),
            totalPages: Math.ceil(totalCount / parseInt(limit)),
          },
        });
      } catch (error) {
        console.error('Error fetching requests:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch requests',
          error: error.message,
        });
      }
    });

    // Direct assignment (HR only) to already-affiliated employees
    app.post('/assets/:id/assign', verifyToken, verifyHR, async (req, res) => {
      try {
        const { id } = req.params;
        const { employeeEmail, notes } = req.body;
        const hrEmail = req.user.email;
        const { ObjectId } = require('mongodb');

        if (!employeeEmail) {
          return res.status(400).send({
            success: false,
            message: 'Employee email is required',
          });
        }

        const employee = await usersCollection.findOne({ email: employeeEmail });
        if (!employee || employee.role !== 'employee') {
          return res.status(404).send({
            success: false,
            message: 'Employee not found',
          });
        }

        // Ensure employee is already affiliated with this HR/company
        const affiliation = await employeeAffiliationsCollection.findOne({
          employeeEmail,
          companyEmail: hrEmail,
          status: 'active',
        });

        if (!affiliation) {
          return res.status(400).send({
            success: false,
            message: 'Employee is not affiliated with your company. Approve a request first.',
          });
        }

        // Get asset and ensure it belongs to this HR and has stock
        const asset = await assetsCollection.findOne({ _id: new ObjectId(id), companyEmail: hrEmail });
        if (!asset) {
          return res.status(404).send({
            success: false,
            message: 'Asset not found for this company',
          });
        }

        if (asset.availableQuantity < 1) {
          return res.status(400).send({
            success: false,
            message: 'Asset is no longer available',
          });
        }

        // Create an approved request entry for traceability
        const now = new Date().toISOString();
        const approvedRequest = {
          assetId: new ObjectId(id),
          assetName: asset.name,
          assetType: asset.type,
          assetImage: asset.image,
          employeeEmail,
          employeeName: employee.name,
          companyEmail: hrEmail,
          companyName: asset.companyName,
          message: notes || 'Direct assignment by HR',
          notes: notes || 'Direct assignment by HR',
          urgency: 'normal',
          status: 'approved',
          requestDate: now,
          approvedDate: now,
          approvedBy: hrEmail,
          createdAt: now,
          updatedAt: now,
        };

        const insertResult = await requestsCollection.insertOne(approvedRequest);

        // Decrease available quantity
        await assetsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $inc: { availableQuantity: -1 }, $set: { updatedAt: now } }
        );

        return res.send({
          success: true,
          message: 'Asset assigned successfully',
          requestId: insertResult.insertedId,
        });
      } catch (error) {
        console.error('Error assigning asset directly:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to assign asset',
          error: error.message,
        });
      }
    });

    // Get employee's assigned assets (My Assets page)
    app.get('/my-assets', verifyToken, async (req, res) => {
      try {
        const { search, type, status, page = 1, limit = 10 } = req.query;
        const employeeEmail = req.user.email;

        let query = {
          employeeEmail,
          status: { $in: ['approved', 'returned'] }, // Show approved and returned assets
        };

        // Status filter
        if (status) {
          query.status = status;
        }

        // Type filter
        if (type) {
          query.assetType = type;
        }

        // Search filter
        if (search) {
          query.$or = [
            { assetName: { $regex: search, $options: 'i' } },
            { companyName: { $regex: search, $options: 'i' } },
          ];
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const totalCount = await requestsCollection.countDocuments(query);

        const assets = await requestsCollection
          .find(query)
          .sort({ updatedAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        return res.send({
          success: true,
          data: assets,
          pagination: {
            total: totalCount,
            page: parseInt(page),
            limit: parseInt(limit),
            totalPages: Math.ceil(totalCount / parseInt(limit)),
          },
        });
      } catch (error) {
        console.error('Error fetching my assets:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch assets',
          error: error.message,
        });
      }
    });


    // Approve request (HR only)
    app.patch('/requests/:id/approve', verifyToken, verifyHR, async (req, res) => {
      try {
        const { id } = req.params;
        const hrEmail = req.user.email;
        const { ObjectId } = require('mongodb');

        // Get the request
        const request = await requestsCollection.findOne({
          _id: new ObjectId(id),
          companyEmail: hrEmail,
          status: 'pending',
        });

        if (!request) {
          return res.status(404).send({
            success: false,
            message: 'Request not found or already processed',
          });
        }

        // Get the asset
        const asset = await assetsCollection.findOne({ _id: request.assetId });
        if (!asset || asset.availableQuantity < 1) {
          return res.status(400).send({
            success: false,
            message: 'Asset is no longer available',
          });
        }

        // Check if this will create a new affiliation - need to verify package limit
        const existingAffiliation = await employeeAffiliationsCollection.findOne({
          employeeEmail: request.employeeEmail,
          companyEmail: hrEmail,
        });

        // Only check limit if this would add a new employee (new affiliation or reactivating removed one)
        const willAddNewEmployee = !existingAffiliation || existingAffiliation.status !== 'active';
        
        if (willAddNewEmployee) {
          const hrUser = await usersCollection.findOne({ email: hrEmail });
          const currentEmployees = hrUser?.currentEmployees || 0;
          const packageLimit = hrUser?.packageLimit || 5;

          if (currentEmployees >= packageLimit) {
            return res.status(400).send({
              success: false,
              message: `Employee limit reached (${currentEmployees}/${packageLimit}). Please upgrade your package to add more employees.`,
            });
          }
        }

        // Update request status
        await requestsCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              status: 'approved',
              approvedDate: new Date().toISOString(),
              approvedBy: hrEmail,
              updatedAt: new Date().toISOString(),
            },
          }
        );

        // Decrease available quantity
        await assetsCollection.updateOne(
          { _id: request.assetId },
          {
            $inc: { availableQuantity: -1 },
            $set: { updatedAt: new Date().toISOString() },
          }
        );

        // Create or reactivate employee affiliation (existingAffiliation already fetched above)
        if (!existingAffiliation) {
          // No affiliation exists - create new one
          await employeeAffiliationsCollection.insertOne({
            employeeEmail: request.employeeEmail,
            employeeName: request.employeeName,
            companyEmail: hrEmail,
            companyName: request.companyName,
            status: 'active',
            affiliatedAt: new Date().toISOString(),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          });

          // Increment HR's employee count
          await usersCollection.updateOne(
            { email: hrEmail },
            { $inc: { currentEmployees: 1 } }
          );
        } else if (existingAffiliation.status !== 'active') {
          // Affiliation exists but inactive/removed - reactivate it
          await employeeAffiliationsCollection.updateOne(
            { _id: existingAffiliation._id },
            {
              $set: {
                status: 'active',
                employeeName: request.employeeName, // Update name in case it changed
                reaffiliatedAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
              },
              $unset: { removedAt: '' }, // Remove the removedAt field
            }
          );

          // Increment HR's employee count (they were decremented when removed)
          await usersCollection.updateOne(
            { email: hrEmail },
            { $inc: { currentEmployees: 1 } }
          );
        }

        return res.send({
          success: true,
          message: 'Request approved successfully',
        });
      } catch (error) {
        console.error('Error approving request:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to approve request',
          error: error.message,
        });
      }
    });

    // Reject request (HR only)
    app.patch('/requests/:id/reject', verifyToken, verifyHR, async (req, res) => {
      try {
        const { id } = req.params;
        const { reason } = req.body;
        const hrEmail = req.user.email;
        const { ObjectId } = require('mongodb');

        const result = await requestsCollection.updateOne(
          {
            _id: new ObjectId(id),
            companyEmail: hrEmail,
            status: 'pending',
          },
          {
            $set: {
              status: 'rejected',
              rejectedDate: new Date().toISOString(),
              rejectedBy: hrEmail,
              rejectionReason: reason || 'No reason provided',
              updatedAt: new Date().toISOString(),
            },
          }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({
            success: false,
            message: 'Request not found or already processed',
          });
        }

        return res.send({
          success: true,
          message: 'Request rejected',
        });
      } catch (error) {
        console.error('Error rejecting request:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to reject request',
          error: error.message,
        });
      }
    });

    // Return asset (Employee returns approved asset)
    app.patch('/requests/:id/return', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const employeeEmail = req.user.email;
        const { ObjectId } = require('mongodb');

        // Get the request
        const request = await requestsCollection.findOne({
          _id: new ObjectId(id),
          employeeEmail,
          status: 'approved',
        });

        if (!request) {
          return res.status(404).send({
            success: false,
            message: 'Request not found or not approved',
          });
        }

        // Check if asset is returnable
        if (request.assetType !== 'returnable') {
          return res.status(400).send({
            success: false,
            message: 'This asset is non-returnable',
          });
        }

        // Update request status
        await requestsCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              status: 'returned',
              returnedDate: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            },
          }
        );

        // Increase available quantity
        await assetsCollection.updateOne(
          { _id: request.assetId },
          {
            $inc: { availableQuantity: 1 },
            $set: { updatedAt: new Date().toISOString() },
          }
        );

        return res.send({
          success: true,
          message: 'Asset returned successfully',
        });
      } catch (error) {
        console.error('Error returning asset:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to return asset',
          error: error.message,
        });
      }
    });

    // Cancel request (Employee cancels own pending request)
    app.patch('/requests/:id/cancel', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const employeeEmail = req.user.email;
        const { ObjectId } = require('mongodb');

        const result = await requestsCollection.updateOne(
          {
            _id: new ObjectId(id),
            employeeEmail,
            status: 'pending',
          },
          {
            $set: {
              status: 'cancelled',
              cancelledDate: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            },
          }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({
            success: false,
            message: 'Request not found or cannot be cancelled',
          });
        }

        return res.send({
          success: true,
          message: 'Request cancelled',
        });
      } catch (error) {
        console.error('Error cancelling request:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to cancel request',
          error: error.message,
        });
      }
    });

    // Get request statistics for HR
    app.get('/requests/stats/summary', verifyToken, verifyHR, async (req, res) => {
      try {
        const hrEmail = req.user.email;

        const stats = await requestsCollection.aggregate([
          { $match: { companyEmail: hrEmail } },
          {
            $group: {
              _id: '$status',
              count: { $sum: 1 },
            },
          },
        ]).toArray();

        // Convert to object
        const summary = {
          pending: 0,
          approved: 0,
          rejected: 0,
          returned: 0,
          cancelled: 0,
          total: 0,
        };

        stats.forEach(s => {
          summary[s._id] = s.count;
          summary.total += s.count;
        });

        return res.send({
          success: true,
          summary,
        });
      } catch (error) {
        console.error('Error fetching request stats:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch request statistics',
          error: error.message,
        });
      }
    });

    // ============ EMPLOYEE AFFILIATIONS ROUTES ============

    // Get HR's employees (affiliated employees)
    app.get('/affiliations/employees', verifyToken, verifyHR, async (req, res) => {
      try {
        const hrEmail = req.user.email;
        const { search, page = 1, limit = 10 } = req.query;

        let query = { companyEmail: hrEmail, status: 'active' };

        if (search) {
          query.$or = [
            { employeeName: { $regex: search, $options: 'i' } },
            { employeeEmail: { $regex: search, $options: 'i' } },
          ];
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const totalCount = await employeeAffiliationsCollection.countDocuments(query);

        const affiliations = await employeeAffiliationsCollection
          .find(query)
          .sort({ affiliatedAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        // Get employee details for each affiliation
        const employeesWithDetails = await Promise.all(
          affiliations.map(async (aff) => {
            const employee = await usersCollection.findOne(
              { email: aff.employeeEmail },
              { projection: { name: 1, email: 1, profileImage: 1, dateOfBirth: 1 } }
            );
            return {
              ...aff,
              employeeDetails: employee,
            };
          })
        );

        return res.send({
          success: true,
          data: employeesWithDetails,
          pagination: {
            total: totalCount,
            page: parseInt(page),
            limit: parseInt(limit),
            totalPages: Math.ceil(totalCount / parseInt(limit)),
          },
        });
      } catch (error) {
        console.error('Error fetching employees:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch employees',
          error: error.message,
        });
      }
    });

    // Get employee's team (other employees at same companies)
    app.get('/affiliations/my-team', verifyToken, async (req, res) => {
      try {
        const { search, company, page = 1, limit = 12 } = req.query;
        const employeeEmail = req.user.email;

        // Get all companies this employee is affiliated with
        const myAffiliations = await employeeAffiliationsCollection
          .find({ employeeEmail, status: 'active' })
          .toArray();

        if (myAffiliations.length === 0) {
          return res.send({
            success: true,
            data: [],
            pagination: { total: 0, page: 1, limit: parseInt(limit), totalPages: 0 },
            message: 'No team affiliations yet',
          });
        }

        // Build query for team members
        let companyEmails = myAffiliations.map(a => a.companyEmail);
        
        // Filter by specific company if provided
        if (company) {
          companyEmails = companyEmails.filter(e => e === company);
        }

        // Get all employees from these companies (including HRs)
        let userQuery = {
          $or: [
            { email: { $in: companyEmails }, role: 'hr' }, // HRs (company owners)
          ],
        };

        // Also get affiliated employees
        const affiliatedEmployeeEmails = await employeeAffiliationsCollection
          .find({ companyEmail: { $in: companyEmails }, status: 'active' })
          .toArray();
        
        const employeeEmails = affiliatedEmployeeEmails.map(a => a.employeeEmail);
        
        // Include both HRs and affiliated employees
        userQuery = {
          $or: [
            { email: { $in: companyEmails }, role: 'hr' },
            { email: { $in: employeeEmails } },
          ],
          email: { $ne: employeeEmail }, // Exclude self
        };

        // Search filter
        if (search) {
          userQuery.$and = [
            userQuery.$or ? { $or: userQuery.$or } : {},
            {
              $or: [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
              ],
            },
          ];
          delete userQuery.$or;
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const totalCount = await usersCollection.countDocuments(userQuery);

        const teamMembers = await usersCollection
          .find(userQuery)
          .project({ name: 1, email: 1, role: 1, profileImage: 1, designation: 1, companyName: 1, dateOfBirth: 1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        // Add company info for employees
        const membersWithCompany = await Promise.all(
          teamMembers.map(async (member) => {
            if (member.role === 'hr') {
              return member;
            }
            // Find employee's affiliation to get company name
            const affiliation = affiliatedEmployeeEmails.find(a => a.employeeEmail === member.email);
            return {
              ...member,
              companyName: affiliation?.companyName || member.companyName,
            };
          })
        );

        return res.send({
          success: true,
          data: membersWithCompany,
          pagination: {
            total: totalCount,
            page: parseInt(page),
            limit: parseInt(limit),
            totalPages: Math.ceil(totalCount / parseInt(limit)),
          },
        });
      } catch (error) {
        console.error('Error fetching team:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch team',
          error: error.message,
        });
      }
    });

    // Remove employee from team (HR only)
    app.delete('/affiliations/:employeeEmail', verifyToken, verifyHR, async (req, res) => {
      try {
        const { employeeEmail } = req.params;
        const hrEmail = req.user.email;

        const result = await employeeAffiliationsCollection.updateOne(
          {
            employeeEmail: decodeURIComponent(employeeEmail),
            companyEmail: hrEmail,
          },
          {
            $set: {
              status: 'removed',
              removedAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            },
          }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({
            success: false,
            message: 'Affiliation not found',
          });
        }

        // Decrement HR's employee count
        await usersCollection.updateOne(
          { email: hrEmail },
          { $inc: { currentEmployees: -1 } }
        );

        return res.send({
          success: true,
          message: 'Employee removed from team',
        });
      } catch (error) {
        console.error('Error removing employee:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to remove employee',
          error: error.message,
        });
      }
    });

    // Get employee's affiliations (companies they work with)
    app.get('/affiliations/my-companies', verifyToken, async (req, res) => {
      try {
        const employeeEmail = req.user.email;

        const affiliations = await employeeAffiliationsCollection
          .find({ employeeEmail, status: 'active' })
          .toArray();

        // Get company details - always use the latest from HR's profile
        const companiesWithDetails = await Promise.all(
          affiliations.map(async (aff) => {
            const hr = await usersCollection.findOne(
              { email: aff.companyEmail },
              { projection: { name: 1, companyName: 1, companyLogo: 1 } }
            );
            return {
              ...aff,
              // Use HR's current company name (source of truth)
              companyName: hr?.companyName || aff.companyName,
              companyLogo: hr?.companyLogo,
              hrName: hr?.name,
            };
          })
        );

        return res.send({
          success: true,
          data: companiesWithDetails,
        });
      } catch (error) {
        console.error('Error fetching companies:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch companies',
          error: error.message,
        });
      }
    });

    // HR Dashboard Stats
    app.get('/stats/hr', verifyToken, verifyHR, async (req, res) => {
      try {
        const hrEmail = req.user.email;

        // Get total assets
        const totalAssets = await assetsCollection.countDocuments({ companyEmail: hrEmail });
        
        // Get available assets
        const availableAssets = await assetsCollection.countDocuments({ 
          companyEmail: hrEmail, 
          availableQuantity: { $gt: 0 } 
        });

        // Get asset types count
        const returnableAssets = await assetsCollection.countDocuments({ 
          companyEmail: hrEmail, 
          type: 'returnable' 
        });
        const nonReturnableAssets = await assetsCollection.countDocuments({ 
          companyEmail: hrEmail, 
          type: 'non-returnable' 
        });

        // Get employee count
        const totalEmployees = await employeeAffiliationsCollection.countDocuments({ 
          companyEmail: hrEmail, 
          status: 'active' 
        });

        // Get request stats
        const totalRequests = await requestsCollection.countDocuments({ companyEmail: hrEmail });
        const pendingRequests = await requestsCollection.countDocuments({ 
          companyEmail: hrEmail, 
          status: 'pending' 
        });
        const approvedRequests = await requestsCollection.countDocuments({ 
          companyEmail: hrEmail, 
          status: 'approved' 
        });
        const rejectedRequests = await requestsCollection.countDocuments({ 
          companyEmail: hrEmail, 
          status: 'rejected' 
        });

        return res.send({
          success: true,
          data: {
            totalAssets,
            availableAssets,
            returnableAssets,
            nonReturnableAssets,
            totalEmployees,
            totalRequests,
            pendingRequests,
            approvedRequests,
            rejectedRequests,
          },
        });
      } catch (error) {
        console.error('Error fetching HR stats:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch stats',
          error: error.message,
        });
      }
    });

    // Employee Dashboard Stats
    app.get('/stats/employee', verifyToken, async (req, res) => {
      try {
        const employeeEmail = req.user.email;

        // Get my requests stats
        const totalRequests = await requestsCollection.countDocuments({ employeeEmail });
        const pendingRequests = await requestsCollection.countDocuments({ 
          employeeEmail, 
          status: 'pending' 
        });
        const approvedRequests = await requestsCollection.countDocuments({ 
          employeeEmail, 
          status: 'approved' 
        });

        // Assets in use (approved)
        const inUseAssets = await requestsCollection.countDocuments({ 
          employeeEmail, 
          status: 'approved' 
        });

        // Returned assets
        const returnedAssets = await requestsCollection.countDocuments({ 
          employeeEmail, 
          status: 'returned' 
        });

        // Total assets (approved + returned)
        const totalAssets = inUseAssets + returnedAssets;

        // Affiliated companies
        const affiliatedCompanies = await employeeAffiliationsCollection.countDocuments({ 
          employeeEmail, 
          status: 'active' 
        });

        return res.send({
          success: true,
          data: {
            totalAssets,
            inUseAssets,
            returnedAssets,
            totalRequests,
            pendingRequests,
            approvedRequests,
            affiliatedCompanies,
          },
        });
      } catch (error) {
        console.error('Error fetching employee stats:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch stats',
          error: error.message,
        });
      }
    });

    // ==================== STRIPE PAYMENT ROUTES ====================

    // Package definitions
    const PACKAGES = {
      basic: { name: 'Basic', employeeLimit: 5, price: 5, priceInCents: 500 },
      standard: { name: 'Standard', employeeLimit: 10, price: 8, priceInCents: 800 },
      premium: { name: 'Premium', employeeLimit: 20, price: 15, priceInCents: 1500 },
    };

    // Create Stripe checkout session (HR only)
    app.post('/create-checkout-session', verifyToken, verifyHR, async (req, res) => {
      try {
        if (!stripe) {
          return res.status(500).send({
            success: false,
            message: 'Payment processing is not configured',
          });
        }

        const { packageType } = req.body;
        const hrEmail = req.user.email;

        // Validate package type
        if (!packageType || !PACKAGES[packageType]) {
          return res.status(400).send({
            success: false,
            message: 'Invalid package type. Choose: basic, standard, or premium',
          });
        }

        const selectedPackage = PACKAGES[packageType];

        // Get current HR data
        const hrUser = await usersCollection.findOne({ email: hrEmail });
        if (!hrUser) {
          return res.status(404).send({
            success: false,
            message: 'User not found',
          });
        }

        // Check if they already have this or better package
        if (hrUser.packageLimit >= selectedPackage.employeeLimit) {
          return res.status(400).send({
            success: false,
            message: `You already have a package with ${hrUser.packageLimit} employees. Choose a higher tier.`,
          });
        }

        // Create Stripe checkout session
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          line_items: [
            {
              price_data: {
                currency: 'usd',
                product_data: {
                  name: `AssetVerse ${selectedPackage.name} Package`,
                  description: `Upgrade to ${selectedPackage.employeeLimit} employee limit`,
                },
                unit_amount: selectedPackage.priceInCents,
              },
              quantity: 1,
            },
          ],
          mode: 'payment',
          success_url: `${allowedOrigins[0]}/dashboard/upgrade-package?success=true&session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${allowedOrigins[0]}/dashboard/upgrade-package?canceled=true`,
          customer_email: hrEmail,
          metadata: {
            hrEmail: hrEmail,
            packageType: packageType,
            newLimit: selectedPackage.employeeLimit.toString(),
            packageName: selectedPackage.name,
          },
        });

        return res.send({
          success: true,
          sessionId: session.id,
          url: session.url,
        });
      } catch (error) {
        console.error('Error creating checkout session:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to create checkout session',
          error: error.message,
        });
      }
    });

    // Verify payment and update package (called after successful payment)
    app.post('/verify-payment', verifyToken, verifyHR, async (req, res) => {
      try {
        if (!stripe) {
          return res.status(500).send({
            success: false,
            message: 'Payment processing is not configured',
          });
        }

        const { sessionId } = req.body;
        const hrEmail = req.user.email;

        if (!sessionId) {
          return res.status(400).send({
            success: false,
            message: 'Session ID is required',
          });
        }

        // Retrieve the session from Stripe
        const session = await stripe.checkout.sessions.retrieve(sessionId);

        // Verify the session
        if (session.payment_status !== 'paid') {
          return res.status(400).send({
            success: false,
            message: 'Payment not completed',
          });
        }

        // Verify the email matches
        if (session.metadata.hrEmail !== hrEmail) {
          return res.status(403).send({
            success: false,
            message: 'Payment session does not belong to this user',
          });
        }

        // Check if this payment was already processed
        const existingPayment = await paymentsCollection.findOne({
          stripeSessionId: sessionId,
        });

        if (existingPayment) {
          return res.send({
            success: true,
            message: 'Payment already processed',
            alreadyProcessed: true,
            data: {
              packageName: existingPayment.packageName,
              newLimit: existingPayment.newLimit,
            },
          });
        }

        const packageType = session.metadata.packageType;
        const newLimit = parseInt(session.metadata.newLimit);
        const packageName = session.metadata.packageName;

        // Update HR's package limit
        await usersCollection.updateOne(
          { email: hrEmail },
          {
            $set: {
              packageLimit: newLimit,
              packageName: packageName,
              packageType: packageType,
              lastUpgradedAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            },
          }
        );

        // Record the payment (guard against duplicate insert if endpoint called twice)
        try {
          await paymentsCollection.insertOne({
            hrEmail: hrEmail,
            stripeSessionId: sessionId,
            stripePaymentIntentId: session.payment_intent,
            packageType: packageType,
            packageName: packageName,
            newLimit: newLimit,
            amountPaid: session.amount_total / 100, // Convert cents to dollars
            currency: session.currency,
            status: 'completed',
            paidAt: new Date().toISOString(),
            createdAt: new Date().toISOString(),
          });
        } catch (err) {
          // Duplicate key (already processed)
          if (err.code === 11000) {
            return res.send({
              success: true,
              message: 'Payment already processed',
              alreadyProcessed: true,
              data: {
                packageName: packageName,
                newLimit: newLimit,
              },
            });
          }
          throw err;
        }

        return res.send({
          success: true,
          message: 'Package upgraded successfully',
          data: {
            packageName: packageName,
            newLimit: newLimit,
          },
        });
      } catch (error) {
        console.error('Error verifying payment:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to verify payment',
          error: error.message,
        });
      }
    });

    // Get payment history (HR only)
    app.get('/payments/history', verifyToken, verifyHR, async (req, res) => {
      try {
        const hrEmail = req.user.email;

        const payments = await paymentsCollection
          .find({ hrEmail })
          .sort({ paidAt: -1 })
          .toArray();

        return res.send({
          success: true,
          data: payments,
        });
      } catch (error) {
        console.error('Error fetching payment history:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch payment history',
          error: error.message,
        });
      }
    });

    // Request refund (HR only) - reverts package to previous state
    app.post('/payments/:paymentId/refund', verifyToken, verifyHR, async (req, res) => {
      try {
        if (!stripe) {
          return res.status(500).send({
            success: false,
            message: 'Payment processing is not configured',
          });
        }

        const { paymentId } = req.params;
        const hrEmail = req.user.email;
        const { ObjectId } = require('mongodb');

        // Find the payment
        const payment = await paymentsCollection.findOne({
          _id: new ObjectId(paymentId),
          hrEmail: hrEmail,
        });

        if (!payment) {
          return res.status(404).send({
            success: false,
            message: 'Payment not found',
          });
        }

        if (payment.status === 'refunded') {
          return res.status(400).send({
            success: false,
            message: 'This payment has already been refunded',
          });
        }

        // Check if user has employees that would exceed the lower limit
        const hrUser = await usersCollection.findOne({ email: hrEmail });
        
        // Determine the previous package limit (the one before this upgrade)
        // Find the payment before this one, or default to 5 (Basic)
        const previousPayment = await paymentsCollection.findOne(
          { 
            hrEmail, 
            paidAt: { $lt: payment.paidAt },
            status: 'completed'
          },
          { sort: { paidAt: -1 } }
        );
        
        const previousLimit = previousPayment ? previousPayment.newLimit : 5;
        const previousPackageName = previousPayment ? previousPayment.packageName : 'Basic';
        const previousPackageType = previousPayment ? previousPayment.packageType : 'basic';

        // Check if current employees exceed previous limit
        if (hrUser.currentEmployees > previousLimit) {
          return res.status(400).send({
            success: false,
            message: `Cannot refund: You have ${hrUser.currentEmployees} employees but the previous package only allows ${previousLimit}. Please remove some employees first.`,
          });
        }

        // Process refund through Stripe
        const refund = await stripe.refunds.create({
          payment_intent: payment.stripePaymentIntentId,
        });

        // Update payment record
        await paymentsCollection.updateOne(
          { _id: new ObjectId(paymentId) },
          {
            $set: {
              status: 'refunded',
              refundedAt: new Date().toISOString(),
              stripeRefundId: refund.id,
              previousLimit: payment.newLimit, // Store what the limit was
              revertedToLimit: previousLimit,
              updatedAt: new Date().toISOString(),
            },
          }
        );

        // Revert user's package limit to previous state
        await usersCollection.updateOne(
          { email: hrEmail },
          {
            $set: {
              packageLimit: previousLimit,
              packageName: previousPackageName,
              packageType: previousPackageType,
              lastRefundedAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            },
          }
        );

        return res.send({
          success: true,
          message: 'Refund processed successfully',
          data: {
            refundId: refund.id,
            previousLimit: previousLimit,
            packageName: previousPackageName,
          },
        });
      } catch (error) {
        console.error('Error processing refund:', error);
        
        // Handle Stripe-specific errors
        if (error.type === 'StripeInvalidRequestError') {
          return res.status(400).send({
            success: false,
            message: error.message || 'Stripe refund failed',
          });
        }

        return res.status(500).send({
          success: false,
          message: 'Failed to process refund',
          error: error.message,
        });
      }
    });

    // Get available packages
    app.get('/packages/available', verifyToken, async (req, res) => {
      try {
        const packages = Object.entries(PACKAGES).map(([key, value]) => ({
          id: key,
          ...value,
        }));

        return res.send({
          success: true,
          data: packages,
        });
      } catch (error) {
        console.error('Error fetching packages:', error);
        return res.status(500).send({
          success: false,
          message: 'Failed to fetch packages',
          error: error.message,
        });
      }
    });

    app.get('/', (req, res) => {
      res.send('AssetVerse server is running');
    });

    app.listen(port, () => {
      console.log(`AssetVerse server listening on port ${port}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
  }
}

run().catch((error) => console.error(error));

