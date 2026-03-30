# Responsive App Shell Navigation

## Purpose
Defines the application shell for Grainlify across desktop and mobile layouts.

## Primary Navigation
- Dashboard
- Programs
- Bounties
- Settings
- Docs

## Secondary Navigation
Used for section-level tabs, filters, and contextual navigation.

## Breakpoints
- Mobile: 320px – 767px
- Tablet: 768px – 1023px
- Desktop: 1024px+

## Mobile Drawer
- Opened from the top app bar on small screens
- Includes primary navigation items
- Supports long organization names with truncation
- Keeps important actions visible and easy to reach
- Uses large tap targets for mobile usability

## Active State
- Active route is visually distinct
- Active state is shown on desktop and mobile
- `aria-current="page"` is used on active links where applicable

## Disabled Feature Flags
- Future sections are shown in a disabled state
- Disabled items are visibly different
- Optional `Soon` badge clarifies status

## Breadcrumb Rules
- Do not show breadcrumbs on top-level landing pages
- Show breadcrumbs on detail pages
- Example: `Dashboard / Reports`
- Example: `Programs / Program Details`

## Contextual Actions
- Important actions should remain directly visible
- Critical actions should not be hidden inside overflow menus

## External Links
- Docs links open in a new tab
- Internal application routes open in the same tab

## Edge Cases
- Long org/workspace names should truncate cleanly
- Many nav items should remain usable on mobile
- Keyboard focus order should follow visual order
- Mobile tap target sizing should remain accessible