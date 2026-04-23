# AssetVerse Server (Backend)

**Full-stack Asset Management System - Backend API**

A robust Node.js/Express backend server providing RESTful APIs for asset tracking, employee management, and request approval workflows with Firebase Authentication, MongoDB Atlas, Stripe payments, and Cloudinary image uploads.

## 🚀 Live Demo

- **API Base URL**: https://assestverse-serverside.vercel.app
- **Client URL**: https://assestverse-clientside.web.app
- **Test Health**: https://assestverse-serverside.vercel.app/

## 📋 Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Environment Variables](#environment-variables)
- [Installation](#installation)
- [API Endpoints](#api-endpoints)
- [Database Schema](#database-schema)
- [Deployment](#deployment)
- [License](#license)

## ✨ Features

### Authentication & Authorization

- 🔐 Firebase JWT token verification
- 🍪 Secure HTTP-only cookie-based sessions
- 👥 Role-based access control (HR & Employee)
- 🔄 Token refresh mechanism

### Asset Management (HR)

- ➕ Create, read, update, delete assets
- 📊 Real-time inventory tracking
- 🔍 Advanced search, filter, and sort
- 📈 Asset analytics and statistics
- 📷 Image upload via Cloudinary
- 🏷️ Categorization and tagging

### Request Management

- 📝 Employee asset requests
- ✅ HR approval/rejection workflow
- 🔄 Asset return for returnable items
- 📊 Request status tracking
- 🔔 Real-time status updates

### Employee Management

- 👥 Employee affiliation system
- 📊 Team member tracking
- 👤 Employee profile management
- 🏢 Multi-company support
- 📈 Package-based employee limits

### Payment Integration

- 💳 Stripe payment processing
- 📦 Package upgrade system (Basic, Standard, Premium)
- 💰 Payment history tracking
- ♻️ Refund management
- 🎯 Employee limit enforcement

### Image Management

- ☁️ Cloudinary integration
- 📁 Organized folder structure
- 🔐 Secure signed uploads
- 🖼️ Direct and client-side upload support

### 🤖 AI Features (Powered by Google Gemini)

- ✨ **Smart Description Generator** - AI-generated professional asset descriptions
- 🏷️ **Auto-Categorization** - Automatic category and type suggestions for new assets
- 🔍 **Natural Language Search** - Search assets using conversational queries
- 📊 **AI Dashboard Insights** - Intelligent analytics and recommendations for HR
- ⚡ **Request Priority Analyzer** - AI-powered prioritization of pending requests
- 💬 **AI Chatbot Assistant** - Interactive help for employees and HR managers
- 🎯 **Asset Recommendations** - Personalized suggestions for employees

## 🛠️ Tech Stack

- **Runtime**: Node.js 18+
- **Framework**: Express.js
- **Database**: MongoDB Atlas
- **Authentication**: Firebase Admin SDK
- **Payment**: Stripe
- **Image Storage**: Cloudinary
- **AI**: Google Gemini 2.0 Flash (Free Tier)
- **Security**: JWT, Cookie-Parser, CORS
- **Deployment**: Vercel (Serverless)

## 🔑 Environment Variables

Create a `.env` file in the root directory:

```env
# Server Configuration
NODE_ENV=production
PORT=5000

# Database
MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>/assetverse?retryWrites=true&w=majority

# Authentication
JWT_SECRET=your_jwt_secret_key_here

# Client CORS (comma-separated for multiple origins)
CLIENT_ORIGIN=https://your-client.web.app,https://your-client.firebaseapp.com,http://localhost:5173

# Firebase Admin SDK (base64 encoded service account key)
# Run: node encode.js to generate this
FB_SERVICE_KEY=base64_encoded_firebase_service_account_key

# Stripe Payment
STRIPE_SECRET_KEY=sk_test_or_live_key

# Cloudinary
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
```

## 📦 Installation

### Prerequisites

- Node.js 18 or higher
- MongoDB Atlas account
- Firebase project
- Vercel account (for deployment)
- Stripe account (optional)
- Cloudinary account (optional)

### Local Development

1. **Clone the repository**

```bash
git clone https://github.com/your-username/assetverse-server.git
cd assetverse-server
```

2. **Install dependencies**

```bash
npm install
```

3. **Configure environment variables**

```bash
cp .env.example .env
# Edit .env with your credentials
```

4. **Encode Firebase Service Key** (for production)

```bash
node encode.js
# Copy the output to FB_SERVICE_KEY in .env
```

5. **Start development server**

```bash
npm start
```

Server will be running at `http://localhost:5000`

## 🌐 API Endpoints

### Authentication

```
POST   /jwt                    - Exchange Firebase token for JWT
POST   /logout                 - Clear authentication cookie
```

### Users

```
POST   /users                  - Register new user
GET    /users/:email           - Get user by email
PATCH  /users/:email           - Update user profile
GET    /users/check/:email     - Check if email exists
```

### Assets (HR Only)

```
POST   /assets                 - Create new asset
GET    /assets                 - Get all assets (with filters)
GET    /assets/available       - Get available assets
GET    /assets/:id             - Get single asset
PATCH  /assets/:id             - Update asset
DELETE /assets/:id             - Delete asset
POST   /assets/:id/assign      - Direct assign asset to employee
GET    /assets/stats/summary   - Get asset statistics
```

### Requests

```
POST   /requests               - Create asset request (Employee)
GET    /requests               - Get requests (filtered by role)
PATCH  /requests/:id/approve   - Approve request (HR)
PATCH  /requests/:id/reject    - Reject request (HR)
PATCH  /requests/:id/return    - Return asset (Employee)
PATCH  /requests/:id/cancel    - Cancel request (Employee)
GET    /requests/stats/summary - Get request statistics (HR)
```

### Employee Affiliations

```
GET    /affiliations/employees     - Get HR's employees
GET    /affiliations/my-team       - Get employee's team
GET    /affiliations/my-companies  - Get employee's companies
DELETE /affiliations/:email        - Remove employee (HR)
```

### My Assets (Employee)

```
GET    /my-assets              - Get employee's assigned assets
```

### Statistics

```
GET    /stats/hr               - Get HR dashboard statistics
GET    /stats/employee         - Get Employee dashboard statistics
```

### Packages

```
GET    /packages               - Get all packages
GET    /packages/:id           - Get package by ID
GET    /packages/name/:name    - Get package by name
GET    /packages/available     - Get available packages
```

### Payments (Stripe)

```
POST   /create-checkout-session    - Create Stripe checkout
POST   /verify-payment              - Verify payment & upgrade
GET    /payments/history            - Get payment history (HR)
POST   /payments/:id/refund         - Request refund (HR)
GET    /payments/config             - Get payment configuration
```

### Cloudinary

```
POST   /cloudinary/signature        - Generate upload signature
POST   /cloudinary/upload           - Direct upload to Cloudinary
POST   /cloudinary/init-folders     - Initialize folder structure
GET    /cloudinary/config           - Get Cloudinary configuration
```

## 📊 Database Schema

### Users Collection

```javascript
{
  name: String,
  email: String (unique),
  role: String (enum: 'hr', 'employee'),
  profileImage: String,
  dateOfBirth: Date,
  companyName: String (for HR),
  companyLogo: String (for HR),
  packageName: String (for HR),
  packageLimit: Number (for HR),
  currentEmployees: Number (for HR),
  createdAt: ISODate,
  updatedAt: ISODate
}
```

### Assets Collection

```javascript
{
  name: String,
  type: String (enum: 'returnable', 'non-returnable'),
  category: String,
  quantity: Number,
  availableQuantity: Number,
  image: String,
  description: String,
  companyEmail: String,
  companyName: String,
  status: String,
  createdAt: ISODate,
  updatedAt: ISODate
}
```

### Requests Collection

```javascript
{
  assetId: ObjectId,
  assetName: String,
  assetType: String,
  employeeEmail: String,
  employeeName: String,
  companyEmail: String,
  companyName: String,
  status: String (enum: 'pending', 'approved', 'rejected', 'returned', 'cancelled'),
  message: String,
  requestDate: ISODate,
  approvedDate: ISODate,
  createdAt: ISODate,
  updatedAt: ISODate
}
```

### Employee Affiliations Collection

```javascript
{
  employeeEmail: String,
  employeeName: String,
  companyEmail: String,
  companyName: String,
  status: String (enum: 'active', 'removed'),
  affiliatedAt: ISODate,
  createdAt: ISODate,
  updatedAt: ISODate
}
```

### Payments Collection

```javascript
{
  hrEmail: String,
  stripeSessionId: String (unique),
  stripePaymentIntentId: String (unique),
  packageType: String,
  packageName: String,
  newLimit: Number,
  amountPaid: Number,
  currency: String,
  status: String,
  paidAt: ISODate,
  createdAt: ISODate
}
```

## 🚀 Deployment

### Deploy to Vercel

1. **Install Vercel CLI**

```bash
npm install -g vercel
```

2. **Login to Vercel**

```bash
vercel login
```

3. **Deploy**

```bash
vercel --prod
```

4. **Configure Environment Variables**

- Go to Vercel Dashboard → Your Project
- Settings → Environment Variables
- Add all variables from `.env`
- **Important**: Use the base64 encoded Firebase key from `node encode.js`

5. **Redeploy** after adding environment variables

### MongoDB Setup

1. Go to MongoDB Atlas
2. Security → Network Access
3. Add IP Address → Allow from Anywhere (0.0.0.0/0)
4. Verify user has Read/Write permissions

### Testing Deployment

```bash
# Health check
curl https://your-server.vercel.app/

# Config check
curl https://your-server.vercel.app/payments/config
```

## 📝 Scripts

```bash
npm start              # Start production server
npm run dev            # Start development server
npm run seed           # Seed packages data
npm run seed:force     # Force seed (drop existing)
npm run seed:all       # Seed packages + sample assets
```

## 🔒 Security Features

- ✅ JWT-based authentication
- ✅ HTTP-only secure cookies
- ✅ Role-based access control
- ✅ CORS protection
- ✅ Environment variable encryption
- ✅ Input validation
- ✅ MongoDB injection prevention
- ✅ Rate limiting ready

## 🐛 Troubleshooting

### Gateway Timeout (504)

- MongoDB ping command is commented out for Vercel compatibility

### CORS Errors

- Ensure `CLIENT_ORIGIN` includes all client URLs (comma-separated)
- Redeploy after updating environment variables

### MongoDB Connection Failed

- Check IP whitelist (0.0.0.0/0)
- Verify connection string format
- Ensure user has correct permissions

### Firebase Token Verification Failed

- Verify `FB_SERVICE_KEY` is base64 encoded correctly
- Re-run `node encode.js` and update

## 📄 License

MIT License - feel free to use this project for learning and commercial purposes.

## 👨‍💻 Author

**Abbas Yasin**

- GitHub: [@abbasyasin1n2](https://github.com/abbasyasin1n2)

## 🆕 Recent Updates

### v2.0 - January 2026

- **Public Assets API**: New `/assets/public/browse` and `/assets/public/:id` endpoints for non-authenticated browsing
- **Aggregation Queries**: Replaced `distinct()` with aggregation pipelines for MongoDB Versioned API compatibility
- **Enhanced Filtering**: Company, category, and type filters for public asset browsing
- **Related Assets**: Asset details now include related assets from the same company
- **Pagination Support**: All list endpoints support proper pagination with total counts

### New Public Endpoints

```
GET    /assets/public/browse   - Browse all available assets (no auth required)
GET    /assets/public/:id      - Get asset details with related assets (no auth required)
```

## 🙏 Acknowledgments

- Firebase for authentication
- MongoDB Atlas for database
- Vercel for hosting
- Stripe for payments
- Cloudinary for image storage

---

**Built with ❤️ using Node.js and Express**
