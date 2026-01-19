# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Commands

### Development
```bash
npm run dev          # Start development server on http://localhost:3000
npm run build        # Build production bundle
npm start            # Start production server
npm run lint         # Run ESLint
```

### Testing
This project does not currently have a test suite configured. When adding tests, update this section.

## Environment Setup

Required environment variables in `.env.local`:
- `MONGODB_URI` - MongoDB connection string (MongoDB Atlas recommended)
- `JWT_SECRET` - Secret for JWT token generation
- `NEXT_PUBLIC_IMAGEKIT_PUBLIC_KEY`, `IMAGEKIT_PRIVATE_KEY`, `NEXT_PUBLIC_IMAGEKIT_URL_ENDPOINT` - ImageKit configuration for image uploads
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` - SMTP configuration for sending emails (OTP, notifications)

Note: `.env.local` contains sensitive credentials - never commit this file.

## Architecture Overview

### Tech Stack
- **Framework**: Next.js 16 with App Router
- **Database**: MongoDB with Mongoose ODM
- **State Management**: Redux Toolkit (@reduxjs/toolkit)
- **Authentication**: JWT with bcrypt password hashing
- **Email**: Nodemailer with SMTP
- **Image Management**: ImageKit
- **UI**: React 19, Tailwind CSS 4, Lucide React icons
- **Editor**: CKEditor 5 for rich text editing

### Directory Structure

```
app/                      # Next.js App Router pages and API routes
  ├── api/               # Backend API routes
  │   ├── auth/          # Authentication endpoints (login, register, OTP, password reset)
  │   ├── profiles/      # Profile/service CRUD operations
  │   ├── favorites/     # User favorites management
  │   ├── seo/           # SEO metadata management
  │   ├── services/      # Service listings
  │   └── upload/        # Image upload to ImageKit
  ├── dashboard/         # Dashboard pages (admin, agency, escort)
  ├── login/             # Login page
  ├── register/          # Registration page
  ├── profile/           # Individual profile pages
  ├── services/          # Services listing page
  └── favorites/         # User favorites page

components/              # Reusable React components
  ├── ClientLayout.js    # Redux Provider wrapper (client component)
  ├── Navbar.js          # Global navigation
  ├── Footer.js          # Global footer
  ├── HomeCard.js        # Profile cards for homepage
  ├── ProfileCard.js     # Profile display cards
  ├── LoginForm.js       # Login form with OTP support
  ├── RegistrationForm.js # Multi-step registration form
  ├── ImageUpload.js     # ImageKit integration component
  └── ...                # Additional UI components

lib/                     # Core utilities and configurations
  ├── db.js              # MongoDB connection handler (singleton pattern)
  ├── store.js           # Redux store configuration
  ├── email.js           # Email sending utility (Nodemailer)
  ├── utils.js           # Utility functions (slugify, etc.)
  ├── models/            # Mongoose schemas
  │   ├── User.js        # User model (escort, agency, admin, visitor roles)
  │   ├── Service.js     # Profile/service model
  │   ├── Favorite.js    # User favorites
  │   └── SEO.js         # SEO metadata
  ├── slices/            # Redux Toolkit slices
  │   ├── authSlice.js   # Authentication state (login, register, OTP)
  │   ├── profileSlice.js # Profile/service state
  │   └── seoSlice.js    # SEO metadata state
  └── hooks/             # Custom React hooks
      └── useEscortData.js

public/                  # Static assets
scripts/                 # Utility scripts
```

### Key Architectural Patterns

#### 1. Authentication Flow
- JWT-based authentication stored in localStorage
- Multi-step registration with OTP email verification
- Role-based access control (admin, agency, escort, visitor)
- Password reset via OTP email
- User blocking capability with reason tracking

User roles:
- `admin` - Full system access, can manage all profiles
- `agency` - Can manage multiple escort profiles
- `escort` - Can manage own profile
- `visitor` - Read-only access, can save favorites
- `landlord` - (defined in schema, usage TBD)

#### 2. Data Models

**User** (`lib/models/User.js`):
- Authentication fields (email, password, OTP, reset tokens)
- Role-based permissions
- Account status (isBlocked, isVerified)
- Favorites reference

**Service** (`lib/models/Service.js`):
- Profile information (name, description, gallery, stats)
- Services offered with pricing
- Status tracking (Active, Inactive, Pending Review)
- Visibility control
- Creator tracking (createdBy, creatorRole, agencyName)
- Moderation fields (idVerificationStatus, photoModerationStatus, internalNotes)

#### 3. State Management (Redux)
Three main slices:
- **authSlice**: Handles registration flow, OTP verification, login state
- **profileSlice**: Manages profile/service data with caching
- **seoSlice**: Manages SEO metadata

Redux is initialized in `components/ClientLayout.js` which wraps the app in `app/layout.js`.

#### 4. Database Connection
MongoDB connection uses singleton pattern in `lib/db.js`:
- Reuses existing connection if available (prevents connection pool exhaustion)
- Connection string from `MONGODB_URI` environment variable
- All API routes call `connectDB()` before database operations

#### 5. API Routes Structure
All API routes follow Next.js App Router conventions:
- Located in `app/api/` directory
- Export HTTP method functions (GET, POST, etc.)
- Use `connectDB()` for database access
- Return `Response` objects with JSON

#### 6. Image Management
ImageKit integration for image uploads:
- Upload endpoint at `/api/upload`
- `ImageUpload` component handles client-side uploads
- Gallery support for multiple images per profile

#### 7. Email System
Uses Nodemailer with SMTP for:
- OTP verification emails (registration and password reset)
- Account notifications
- Configured via environment variables

## Development Guidelines

### Adding New API Routes
1. Create route file in `app/api/[route-name]/route.js`
2. Always call `await connectDB()` before database operations
3. Use try-catch for error handling
4. Return proper HTTP status codes
5. Include JWT verification for protected routes

Example:
```javascript
import { connectDB } from "@/lib/db";
import Model from "@/lib/models/Model";

export async function GET() {
  try {
    await connectDB();
    const data = await Model.find();
    return new Response(JSON.stringify(data), { status: 200 });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
```

### Working with Redux
1. Add async operations as thunks in slices
2. Update `lib/store.js` to include new slice reducers
3. Use `useDispatch` and `useSelector` in components
4. Keep state normalized to avoid duplication

### Protected Routes
Client-side route protection pattern:
1. Check for JWT token in localStorage
2. Verify token via `/api/auth/verify` endpoint
3. Check user role matches required permissions
4. Redirect to `/login` if unauthorized

### Image Uploads
Use `ImageUpload` component for all image uploads:
- Handles ImageKit authentication
- Returns uploaded image URLs
- Supports single and multiple uploads

### Database Models
When creating/modifying Mongoose models:
- Use `mongoose.models.ModelName || mongoose.model("ModelName", schema)` to avoid recompilation errors in development
- Add timestamps with `{ timestamps: true }` option
- Use proper field validation and defaults
- Add indexes for frequently queried fields

### Environment Configuration
- Development runs on port 3000 by default
- MongoDB connection must be established before server starts
- ImageKit credentials required for image uploads
- SMTP credentials required for email functionality

## Known Issues & TODO

Check `TODO.md` for current project status and known issues.

Current notable issues:
- MongoDB connection needs to be properly configured (see TODO.md)
- Admin dashboard profile editing/deletion not fully implemented
- Test suite not yet created

## Deployment Notes

When deploying:
1. Ensure all environment variables are set in production
2. Run `npm run build` to verify build succeeds
3. MongoDB Atlas recommended over local MongoDB for production
4. Configure proper SMTP service for production emails
5. Set `NODE_ENV=production` in environment
