/**
 * Database Seed Script
 * Run with: node scripts/seed.js
 * 
 * This script seeds initial data into MongoDB:
 * - Packages (subscription tiers)
 * - Sample assets (optional, for development)
 */

require('dotenv').config();
const { MongoClient, ServerApiVersion } = require('mongodb');

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI not found in .env file');
  process.exit(1);
}

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
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
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
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
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
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
];

// Sample assets for development/testing
const sampleAssets = [
  {
    name: 'MacBook Pro 14"',
    type: 'returnable',
    category: 'Laptop',
    quantity: 10,
    availableQuantity: 8,
    image: 'https://res.cloudinary.com/demo/image/upload/v1/samples/ecommerce/laptop.jpg',
    description: 'Apple MacBook Pro 14-inch with M3 Pro chip, 18GB RAM, 512GB SSD',
    purchaseDate: '2024-01-15',
    purchasePrice: 250000,
    currency: 'BDT',
    status: 'available',
  },
  {
    name: 'Dell UltraSharp 27" Monitor',
    type: 'returnable',
    category: 'Monitor',
    quantity: 15,
    availableQuantity: 12,
    image: 'https://res.cloudinary.com/demo/image/upload/v1/samples/ecommerce/monitor.jpg',
    description: '4K UHD monitor with USB-C connectivity',
    purchaseDate: '2024-02-20',
    purchasePrice: 45000,
    currency: 'BDT',
    status: 'available',
  },
  {
    name: 'Ergonomic Office Chair',
    type: 'returnable',
    category: 'Furniture',
    quantity: 20,
    availableQuantity: 15,
    image: 'https://res.cloudinary.com/demo/image/upload/v1/samples/ecommerce/chair.jpg',
    description: 'High-back ergonomic chair with lumbar support',
    purchaseDate: '2024-01-10',
    purchasePrice: 25000,
    currency: 'BDT',
    status: 'available',
  },
  {
    name: 'Wireless Mouse',
    type: 'non-returnable',
    category: 'Accessories',
    quantity: 50,
    availableQuantity: 45,
    image: 'https://res.cloudinary.com/demo/image/upload/v1/samples/ecommerce/mouse.jpg',
    description: 'Logitech MX Master 3S wireless mouse',
    purchaseDate: '2024-03-01',
    purchasePrice: 8500,
    currency: 'BDT',
    status: 'available',
  },
  {
    name: 'Mechanical Keyboard',
    type: 'non-returnable',
    category: 'Accessories',
    quantity: 30,
    availableQuantity: 28,
    image: 'https://res.cloudinary.com/demo/image/upload/v1/samples/ecommerce/keyboard.jpg',
    description: 'Keychron K2 wireless mechanical keyboard',
    purchaseDate: '2024-02-15',
    purchasePrice: 9000,
    currency: 'BDT',
    status: 'available',
  },
  {
    name: 'Notebook Pack (50 pcs)',
    type: 'non-returnable',
    category: 'Stationery',
    quantity: 100,
    availableQuantity: 85,
    image: 'https://res.cloudinary.com/demo/image/upload/v1/samples/ecommerce/notebook.jpg',
    description: 'Premium A4 notebooks for office use',
    purchaseDate: '2024-03-10',
    purchasePrice: 2500,
    currency: 'BDT',
    status: 'available',
  },
  {
    name: 'Pen Set (Box of 100)',
    type: 'non-returnable',
    category: 'Stationery',
    quantity: 200,
    availableQuantity: 180,
    image: 'https://res.cloudinary.com/demo/image/upload/v1/samples/ecommerce/pen.jpg',
    description: 'Blue ballpoint pens for daily office use',
    purchaseDate: '2024-03-15',
    purchasePrice: 1500,
    currency: 'BDT',
    status: 'available',
  },
  {
    name: 'iPhone 15 Pro',
    type: 'returnable',
    category: 'Phone',
    quantity: 5,
    availableQuantity: 3,
    image: 'https://res.cloudinary.com/demo/image/upload/v1/samples/ecommerce/iphone.jpg',
    description: 'Apple iPhone 15 Pro 256GB for company executives',
    purchaseDate: '2024-01-20',
    purchasePrice: 180000,
    currency: 'BDT',
    status: 'available',
  },
];

async function seed() {
  const client = new MongoClient(MONGODB_URI, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
  });

  try {
    await client.connect();
    console.log('✅ Connected to MongoDB');

    const db = client.db('assetverse');

    // Seed Packages
    console.log('\n📦 Seeding packages...');
    const packagesCollection = db.collection('packages');
    const existingPackages = await packagesCollection.countDocuments();

    if (existingPackages > 0) {
      console.log(`   ⚠️  Packages already exist (${existingPackages} found). Skipping...`);
      console.log('   💡 To reseed, run: node scripts/seed.js --force');
    } else {
      const result = await packagesCollection.insertMany(defaultPackages);
      console.log(`   ✅ Inserted ${result.insertedCount} packages`);
    }

    // Check for --with-assets flag
    if (process.argv.includes('--with-assets')) {
      console.log('\n🏷️  Seeding sample assets...');
      const assetsCollection = db.collection('assets');
      const existingAssets = await assetsCollection.countDocuments();

      if (existingAssets > 0) {
        console.log(`   ⚠️  Assets already exist (${existingAssets} found). Skipping...`);
      } else {
        // Add timestamps and company info placeholder
        const assetsToInsert = sampleAssets.map(asset => ({
          ...asset,
          companyEmail: 'demo@assetverse.com', // Placeholder - will be replaced by actual HR
          companyName: 'Demo Company',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        }));

        const result = await assetsCollection.insertMany(assetsToInsert);
        console.log(`   ✅ Inserted ${result.insertedCount} sample assets`);
      }
    }

    // Force reseed if --force flag is present
    if (process.argv.includes('--force')) {
      console.log('\n🔄 Force reseeding...');
      
      await packagesCollection.deleteMany({});
      const packagesResult = await packagesCollection.insertMany(defaultPackages);
      console.log(`   ✅ Reseeded ${packagesResult.insertedCount} packages`);

      if (process.argv.includes('--with-assets')) {
        const assetsCollection = db.collection('assets');
        await assetsCollection.deleteMany({ companyEmail: 'demo@assetverse.com' });
        
        const assetsToInsert = sampleAssets.map(asset => ({
          ...asset,
          companyEmail: 'demo@assetverse.com',
          companyName: 'Demo Company',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        }));
        
        const assetsResult = await assetsCollection.insertMany(assetsToInsert);
        console.log(`   ✅ Reseeded ${assetsResult.insertedCount} sample assets`);
      }
    }

    console.log('\n✨ Seeding completed successfully!\n');

  } catch (error) {
    console.error('❌ Seeding failed:', error.message);
    process.exit(1);
  } finally {
    await client.close();
    console.log('📤 Disconnected from MongoDB');
  }
}

// Run the seed function
seed();
