# Glassmorphism Landing Page

This is a code bundle for Glassmorphism Landing Page. The original project is available at https://www.figma.com/design/Q7mcDMFYoct92SkOWFAoCP/Glassmorphism-Landing-Page.

## Prerequisites

- **Node.js**: Latest LTS version (recommended: v20.x or higher)
- **pnpm**: Package manager (install globally with `npm install -g pnpm` if not already installed)

## Setup

1. **Install dependencies**:
   ```bash
   pnpm install
   ```

2. **Configure environment variables**:
   ```bash
   cp .env.example .env
   ```
   
   Then edit `.env` and set the required variables:
   - `VITE_API_BASE_URL`: Backend API URL (e.g., `http://localhost:8080`)
   - `VITE_FRONTEND_BASE_URL`: Frontend base URL (optional, defaults to current origin)

Run `pnpm run dev` to start the development server.

## Design System

Grainlify uses a cohesive visual language implemented as design tokens. The design system is WCAG 2.1 AA compliant and aligns with Stellar ecosystem credibility.

### Design Tokens

All visual properties are defined as CSS custom properties in `src/styles/theme.css`:

#### Color Ramps
- **Primary**: Gold scale from 50 (lightest) to 950 (darkest)
- **Neutral**: Warm gray scale for backgrounds and text
- **Semantic**: Success, warning, and error colors

#### Typography Scale
- Font sizes: xs (0.75rem) through 6xl (3.75rem)
- Line heights: tight (1.25), normal (1.5), relaxed (1.75)
- Font weights: thin (100) through black (900)

#### Spacing Grid
- Base unit: 4px (0.25rem)
- Scale: 1 (0.25rem) through 64 (16rem)

#### Border Radius
- Scale: sm (0.125rem) through full (9999px)

#### Elevation
- Shadows: sm through 2xl for depth and layering

### Usage

Tokens are available as CSS variables and Tailwind classes:

```css
/* CSS Variables */
.my-element {
  color: var(--color-primary-600);
  padding: var(--space-4);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-md);
}
```

```html
<!-- Tailwind Classes -->
<div class="bg-primary-600 text-primary-foreground p-4 rounded-lg shadow-md">
  Content
</div>
```

### Accessibility

- All color combinations meet WCAG 2.1 AA contrast requirements
- Focus states use 3:1 contrast ratio minimum
- Dark mode maintains accessibility standards

### Dark Mode

The design system includes full dark mode support. Colors automatically adapt based on the `dark` class on the html element.
