# Timezone Explorer UI

## Overview

A modern, interactive web interface for exploring timezones across different countries. Built with EJS templating engine, vanilla JavaScript, and a beautiful gradient design.

## Features

### 1. **Beautiful UI Design**

- Animated gradient background (purple to blue)
- Smooth animations and transitions
- Responsive design for mobile and desktop
- Modern card-based layout

### 2. **Country Selection**

- Dropdown with all available countries
- Shows timezone count for each country
- Alphabetically sorted for easy navigation
- Real-time data from backend API

### 3. **Timezone Display**

- Clean, organized list of timezones
- Shows timezone name and UTC offset
- Animated entry effects
- Interactive hover states

### 4. **Error Handling**

- User-friendly error messages
- Loading states during API calls
- Graceful fallbacks

## Technical Implementation

### Tech Stack

- **Templating Engine**: EJS v4.0.1
- **Frontend**: Vanilla JavaScript (ES6+)
- **Styling**: Custom CSS3 with animations
- **Backend**: Express.js + TypeScript

### Project Structure

```
express-rest-api/
├── views/
│   └── index.ejs                 # Main page template
├── public/
│   ├── css/
│   │   └── styles.css            # Styling and animations
│   └── js/
│       └── app.js                # Client-side logic
└── src/
    ├── app.ts                    # Express config with EJS setup
    ├── routes/index.ts           # Route definitions
    └── controllers/
        └── index.ts              # View rendering controller
```

### API Endpoints Used

1. **GET /** - Renders the main UI page
2. **GET /api/timezones/countries** - Fetches all countries with timezone counts
3. **GET /api/timezones?countryCode=XX** - Fetches timezones for a specific country

## Configuration

### App Setup (src/app.ts)

```typescript
// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

// Static files
app.use(express.static(path.join(__dirname, '../public')));

// CSP configuration for inline styles/scripts
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
      },
    },
  })
);
```

## Usage

### 1. Start the Server

```bash
pnpm dev          # Development mode
# or
pnpm build && pnpm start  # Production mode
```

### 2. Access the UI

Open your browser and navigate to:

```
http://localhost:3000/
```

### 3. Explore Timezones

1. Select a country from the dropdown
2. Click "Get Timezones" button
3. View the list of timezones with UTC offsets

## Client-Side Flow

```
Page Load
    ↓
Fetch Countries (GET /api/timezones/countries)
    ↓
Populate Dropdown
    ↓
User Selects Country
    ↓
Submit Form
    ↓
Fetch Timezones (GET /api/timezones?countryCode=XX)
    ↓
Display Results with Animation
```

## Design Highlights

### Color Scheme

- Primary: Indigo (#6366f1)
- Secondary: Purple (#8b5cf6)
- Background: Linear gradient (purple to violet)
- Success: Emerald green (#10b981)
- Error: Red (#ef4444)

### Animations

- Background shift animation (15s loop)
- Fade-in effects for headers
- Scale-in for cards
- Slide-in for timezone items
- Shake effect for errors
- Loading dots animation

### Responsive Breakpoints

- Mobile: < 640px
- Desktop: > 640px

## Security Features

1. **Content Security Policy (CSP)**

   - Configured via Helmet.js
   - Allows inline styles/scripts for EJS templates
   - Restricts external resource loading

2. **Input Validation**

   - Client-side form validation
   - Country code validation on server

3. **Error Sanitization**
   - No stack traces exposed to client
   - User-friendly error messages

## Best Practices Followed

✅ **TypeScript strict mode** - Full type safety  
✅ **ES6+ features** - Modern JavaScript syntax  
✅ **Async/await** - Clean asynchronous code  
✅ **Error handling** - Try-catch blocks throughout  
✅ **JSDoc comments** - Well-documented functions  
✅ **Responsive design** - Works on all devices  
✅ **Accessibility** - Semantic HTML, proper labels  
✅ **Performance** - Optimized animations, efficient DOM updates  
✅ **Security** - CSP headers, input validation

## Future Enhancements

- [ ] Search/filter functionality for countries
- [ ] Display current time in selected timezones
- [ ] Timezone comparison feature
- [ ] Dark/light theme toggle
- [ ] Favorite countries persistence
- [ ] Time zone converter tool

## Troubleshooting

### Page Not Loading

- Ensure the server is running (`pnpm dev`)
- Check that views/ and public/ directories exist
- Verify EJS is installed (`pnpm list ejs`)

### Styles Not Applying

- Check browser console for CSP errors
- Verify static files middleware is configured
- Clear browser cache

### API Errors

- Check server logs for details
- Verify timezone controller endpoints are working
- Test API endpoints directly with curl

## Related Files

- [index.ejs](../views/index.ejs) - Main template
- [styles.css](../public/css/styles.css) - Styling
- [app.js](../public/js/app.js) - Client logic
- [index.ts](../src/controllers/index.ts) - View controller
- [timezoneController.ts](../src/controllers/timezoneController.ts) - API controller

---

**Version**: 1.0.0  
**Updated**: February 4, 2026
