require('dotenv').config();

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const { MongoClient, ServerApiVersion } = require('mongodb');
const Stripe = require('stripe');
const cloudinary = require('cloudinary').v2;

const serviceAccount = require('./assestverse-clientside-firebase-adminsdk-serviceAccountKey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
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
const allowedOrigin = process.env.CLIENT_ORIGIN || 'http://localhost:5173';

app.use(
  cors({
    origin: allowedOrigin,
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'none',
  maxAge: 7 * 24 * 60 * 60 * 1000,
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

    await db.command({ ping: 1 });
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
      res.clearCookie('token', { ...cookieOptions, maxAge: 0 });
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

    // Initialize Cloudinary folder structure (creates assestverse/assets and assestverse/users)
    app.post('/cloudinary/init-folders', async (req, res) => {
      try {
        // Create placeholder files in each folder to ensure folders exist
        // Cloudinary creates folders automatically when you upload to them
        const folders = ['assestverse/assets', 'assestverse/users'];
        
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
        
        // Validate folder - only allow uploads to assestverse/assets or assestverse/users
        const allowedFolders = ['assestverse/assets', 'assestverse/users'];
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

    // Direct upload endpoint (server-side upload)
    app.post('/cloudinary/upload', express.raw({ type: 'application/octet-stream', limit: '10mb' }), async (req, res) => {
      try {
        const { folder } = req.query;
        
        const allowedFolders = ['assestverse/assets', 'assestverse/users'];
        if (!folder || !allowedFolders.includes(folder)) {
          return res.status(400).send({
            success: false,
            message: `Invalid folder. Allowed: ${allowedFolders.join(', ')}`,
          });
        }

        // For testing purposes - upload a sample image
        const result = await cloudinary.uploader.upload(
          'data:image/png;base64,' + req.body.toString('base64'),
          {
            folder,
            resource_type: 'auto',
          }
        );

        return res.send({
          success: true,
          message: 'Image uploaded successfully',
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
          assets: 'assestverse/assets',
          users: 'assestverse/users',
        },
      });
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

