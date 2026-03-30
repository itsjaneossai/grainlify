# Grainlify Transactional Email Templates

A responsive, table-based email template system for Grainlify transactional emails. Designed for maximum compatibility across major email clients (Gmail, Apple Mail, Outlook, etc.).

## Overview

This template system provides a consistent, professional look for all Grainlify transactional emails. The templates are built with:

- **Table-based layout** for maximum email client compatibility
- **Responsive design** that works on desktop, tablet, and mobile
- **Dark mode support** with appropriate fallbacks
- **Plain-text alternatives** for accessibility and deliverability
- **Unsubscribe and compliance** features built-in

## Directory Structure

```
backend/email-templates/
├── html/                          # HTML email templates
│   ├── master.html               # Base template for all emails
│   ├── payout-notification.html  # Payout notification template
│   └── bounty-update.html        # Bounty update template
├── text/                          # Plain-text alternatives
│   ├── master.txt                # Plain-text master template
│   ├── payout-notification.txt   # Plain-text payout notification
│   └── bounty-update.txt         # Plain-text bounty update
├── VARIABLES.md                   # Variable documentation for backend
└── README.md                      # This file
```

## Templates

### Master Template

The base template that provides the overall structure for all transactional emails. Includes:

- Header with logo
- Body content area
- CTA button
- Footer with links and compliance information

**Use this as a starting point for new email types.**

### Payout Notification

Sent when a user receives a payout for a completed bounty.

**Key Features:**
- Displays payout amount prominently
- Shows transaction details in a clean box
- Links to transaction on blockchain explorer
- Handles long transaction IDs gracefully

### Bounty Update

Sent when there's an update on a bounty the user is following.

**Key Features:**
- Shows bounty details and reward amount
- Displays update type and description
- Links to bounty details page
- Handles long issue titles

## Quick Start

### 1. Choose a Template

Start with the master template for new email types, or use an existing example template.

### 2. Prepare Your Data

Create a data structure with all required variables. See [VARIABLES.md](VARIABLES.md) for complete documentation.

### 3. Render the Template

Use your preferred templating engine to render the HTML:

```go
// Go example
import "html/template"

tmpl, _ := template.ParseFiles("email-templates/html/payout-notification.html")
var buf bytes.Buffer
tmpl.Execute(&buf, data)
html := buf.String()
```

```javascript
// JavaScript example
const Handlebars = require('handlebars');
const fs = require('fs');

const templateSource = fs.readFileSync('email-templates/html/payout-notification.html', 'utf8');
const template = Handlebars.compile(templateSource);
const html = template(data);
```

### 4. Send the Email

Always send both HTML and plain-text versions:

```go
msg := &mail.Message{
    To:      []string{userEmail},
    Subject: subject,
    HTML:    htmlContent,
    Text:    textContent,
}
```

## Design Principles

### Email Client Compatibility

- **Table-based layout**: Ensures consistent rendering across all clients
- **Inline styles**: Prevents style stripping by email clients
- **MSO conditionals**: Provides Outlook-specific fixes
- **No external CSS**: All styles are inline

### Responsive Design

- **Mobile-first approach**: Designed for small screens first
- **Flexible widths**: Uses max-width and percentage-based layouts
- **Stackable columns**: Columns stack on mobile devices
- **Touch-friendly buttons**: Large, easy-to-tap CTA buttons

### Dark Mode

- **CSS media queries**: Detects dark mode preference
- **High contrast colors**: Ensures readability in both modes
- **Fallback colors**: Provides alternatives if dark mode isn't supported

### Accessibility

- **Semantic HTML**: Uses proper table structure
- **Alt text**: All images have descriptive alt text
- **Color contrast**: Meets WCAG AA standards
- **Plain-text alternatives**: Provides text-only versions

## Compliance

### Unsubscribe Requirements

All templates include:

1. **Unsubscribe link**: One-click unsubscribe functionality
2. **Preference management**: Link to notification settings
3. **Company information**: Physical address and contact info
4. **Clear identification**: Obvious sender identification

### CAN-SPAM Compliance

- Clear sender identification
- Valid physical address
- Honors unsubscribe requests within 10 business days
- Clear, non-deceptive subject lines

### GDPR Compliance

- Privacy policy link
- Data processing information
- Preference management options

## Testing

### Email Client Testing

Test templates in these clients:

- **Gmail**: Web, iOS, Android
- **Apple Mail**: macOS, iOS
- **Outlook**: Web, Desktop (2016, 2019, 365)
- **Yahoo Mail**: Web, Mobile
- **Thunderbird**: Desktop

### Responsive Testing

Test at these widths:

- **Desktop**: 600px+ width
- **Tablet**: 400-600px width
- **Mobile**: <400px width

### Dark Mode Testing

1. Enable dark mode in email client
2. Verify text remains readable
3. Verify links are visible
4. Verify CTA buttons are visible

## Edge Cases

### Long Amounts

Large numbers are handled gracefully with proper formatting:

```
1,234,567.89 XLM
```

### Missing User Name

Fallback to generic greeting:

```
Hi there,
```

### Long Transaction IDs

Transaction IDs wrap properly without breaking layout:

```
abc123def456ghi789jkl012mno345pqr678stu901vwx234yz
```

### Long Issue Titles

Issue titles are truncated if too long:

```
Fix login bug and improve security...
```

## Creating New Templates

### Step 1: Copy Master Template

```bash
cp html/master.html html/my-new-template.html
```

### Step 2: Customize Content

Replace the placeholder content with your specific email content:

1. Update the header tagline
2. Replace `{{main_content}}` with your message
3. Update `{{cta_text}}` and `{{cta_url}}`
4. Add any template-specific variables

### Step 3: Create Plain-Text Version

```bash
cp text/master.txt text/my-new-template.txt
```

Update the plain-text version to match your HTML content.

### Step 4: Document Variables

Add your new variables to [VARIABLES.md](VARIABLES.md) with:

- Variable name and type
- Required or optional
- Description
- Example value

### Step 5: Test

1. Test in multiple email clients
2. Test responsive design
3. Test dark mode
4. Test with edge cases (long text, missing data)

## Implementation Notes

### Backend Integration

The templates are designed to work with any backend templating engine:

- **Go**: `html/template`
- **JavaScript**: Handlebars, Mustache, EJS
- **Python**: Jinja2, Mako
- **Ruby**: ERB, Haml
- **PHP**: Blade, Twig

### URL Generation

All URLs should be:

- **Absolute**: Include full protocol and domain
- **Secure**: Use HTTPS in production
- **Unique**: Include user-specific tokens where needed

### Variable Escaping

Ensure proper escaping for:

- **HTML entities**: `<`, `>`, `&`, `"`, `'`
- **URL encoding**: Special characters in URLs
- **JavaScript**: If embedding in scripts

## Troubleshooting

### Images Not Loading

- Ensure image URLs are absolute
- Use HTTPS for production images
- Provide alt text for all images
- Consider image size for mobile

### Layout Breaking

- Check for missing closing tags
- Verify table structure is correct
- Test in Outlook (most strict client)
- Use MSO conditionals for Outlook fixes

### Dark Mode Issues

- Test in multiple clients
- Use high contrast colors
- Provide fallback colors
- Avoid transparent backgrounds

### Links Not Working

- Ensure URLs are absolute
- Check for proper encoding
- Test in multiple clients
- Verify redirect URLs work

## Support

For questions or issues with email templates:

- **Email**: engineering@grainlify.com
- **Slack**: #engineering channel
- **Documentation**: https://docs.grainlify.com/emails

## Contributing

When adding new templates or modifying existing ones:

1. Follow the design principles outlined above
2. Test in multiple email clients
3. Create both HTML and plain-text versions
4. Document all variables
5. Update this README if needed

## License

These templates are part of the Grainlify project and are subject to the same license.
