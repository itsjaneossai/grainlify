# Email Template Variables Documentation

This document provides a comprehensive guide for backend developers on how to use the Grainlify transactional email templates.

## Table of Contents

- [Overview](#overview)
- [Template Structure](#template-structure)
- [Common Variables](#common-variables)
- [Payout Notification Variables](#payout-notification-variables)
- [Bounty Update Variables](#bounty-update-variables)
- [Implementation Notes](#implementation-notes)
- [Edge Cases](#edge-cases)
- [Testing](#testing)

## Overview

The email template system uses a simple variable substitution approach. Variables are enclosed in double curly braces: `{{variable_name}}`. The backend templating engine should replace these placeholders with actual values before sending the email.

### Template Files

- **HTML Templates**: `backend/email-templates/html/`
  - `master.html` - Base template for all transactional emails
  - `payout-notification.html` - Payout notification template
  - `bounty-update.html` - Bounty update template

- **Plain Text Templates**: `backend/email-templates/text/`
  - `master.txt` - Plain text version of master template
  - `payout-notification.txt` - Plain text version of payout notification
  - `bounty-update.txt` - Plain text version of bounty update

## Template Structure

All templates follow this structure:

1. **Header**: Logo and tagline
2. **Body**: Main content with greeting, message, and CTA
3. **Footer**: Links, unsubscribe option, and company info

## Common Variables

These variables are used across all templates:

### User Information

| Variable | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `{{user_name}}` | string | Yes | User's display name | `"John Doe"` |
| `{{user_email}}` | string | Yes | User's email address | `"john@example.com"` |

### Email Metadata

| Variable | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `{{subject}}` | string | Yes | Email subject line | `"Payout Notification"` |
| `{{preview_text}}` | string | Yes | Preview text shown in email clients | `"Your payout of 100 XLM has been processed"` |

### Branding

| Variable | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `{{logo_url}}` | string | Yes | URL to the Grainlify logo | `"https://grainlify.com/logo.png"` |
| `{{header_tagline}}` | string | No | Tagline shown in header | `"Payout Notification"` |

### URLs

| Variable | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `{{help_url}}` | string | Yes | Help center URL | `"https://help.grainlify.com"` |
| `{{privacy_url}}` | string | Yes | Privacy policy URL | `"https://grainlify.com/privacy"` |
| `{{terms_url}}` | string | Yes | Terms of service URL | `"https://grainlify.com/terms"` |
| `{{unsubscribe_url}}` | string | Yes | Unsubscribe URL | `"https://grainlify.com/unsubscribe?token=abc123"` |
| `{{notification_preferences_url}}` | string | Yes | Notification preferences URL | `"https://grainlify.com/settings/notifications"` |

### Company Information

| Variable | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `{{company_name}}` | string | Yes | Company name | `"Grainlify"` |
| `{{company_address}}` | string | Yes | Company address | `"123 Blockchain St, Crypto City, CC 12345"` |
| `{{current_year}}` | string | Yes | Current year | `"2026"` |

## Payout Notification Variables

### Required Variables

| Variable | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `{{payout_amount}}` | string | Yes | Payout amount | `"100.50"` |
| `{{token_symbol}}` | string | Yes | Token symbol | `"XLM"` |
| `{{project_name}}` | string | Yes | Project name | `"Stellar DEX"` |
| `{{issue_number}}` | string | Yes | GitHub issue number | `"42"` |
| `{{transaction_id}}` | string | Yes | Blockchain transaction ID | `"abc123def456..."` |
| `{{payout_date}}` | string | Yes | Payout date | `"March 30, 2026"` |
| `{{transaction_url}}` | string | Yes | URL to view transaction details | `"https://stellar.expert/tx/abc123"` |

### Optional Variables

| Variable | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `{{secondary_content}}` | string | No | Additional content below CTA | `"Note: This payout includes a bonus for early completion."` |

## Bounty Update Variables

### Required Variables

| Variable | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `{{issue_number}}` | string | Yes | GitHub issue number | `"42"` |
| `{{issue_title}}` | string | Yes | Issue title | `"Fix login bug"` |
| `{{project_name}}` | string | Yes | Project name | `"Stellar DEX"` |
| `{{reward_amount}}` | string | Yes | Reward amount | `"500"` |
| `{{token_symbol}}` | string | Yes | Token symbol | `"XLM"` |
| `{{update_type}}` | string | Yes | Type of update | `"New applicant"` |
| `{{update_date}}` | string | Yes | Update date | `"March 30, 2026"` |
| `{{update_description}}` | string | Yes | Description of the update | `"A new contributor has applied to work on this bounty."` |
| `{{bounty_url}}` | string | Yes | URL to view bounty details | `"https://grainlify.com/bounties/42"` |

### Optional Variables

| Variable | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `{{secondary_content}}` | string | No | Additional content below CTA | `"You can also view the full discussion on GitHub."` |

## Implementation Notes

### Templating Engine Integration

The templates are designed to work with common templating engines:

#### Go (html/template)

```go
import (
    "html/template"
    "bytes"
)

type PayoutEmailData struct {
    UserName              string
    PayoutAmount          string
    TokenSymbol           string
    ProjectName           string
    IssueNumber           string
    TransactionID         string
    PayoutDate            string
    TransactionURL        string
    LogoURL               string
    HelpURL               string
    PrivacyURL            string
    TermsURL              string
    UnsubscribeURL        string
    NotificationPrefsURL  string
    CompanyName           string
    CompanyAddress        string
    CurrentYear           string
}

func RenderPayoutTemplate(data PayoutEmailData) (string, error) {
    tmpl, err := template.ParseFiles("email-templates/html/payout-notification.html")
    if err != nil {
        return "", err
    }
    
    var buf bytes.Buffer
    if err := tmpl.Execute(&buf, data); err != nil {
        return "", err
    }
    
    return buf.String(), nil
}
```

#### JavaScript (Handlebars)

```javascript
const Handlebars = require('handlebars');
const fs = require('fs');

const templateSource = fs.readFileSync('email-templates/html/payout-notification.html', 'utf8');
const template = Handlebars.compile(templateSource);

const data = {
    userName: 'John Doe',
    payoutAmount: '100.50',
    tokenSymbol: 'XLM',
    projectName: 'Stellar DEX',
    issueNumber: '42',
    transactionId: 'abc123def456...',
    payoutDate: 'March 30, 2026',
    transactionUrl: 'https://stellar.expert/tx/abc123',
    logoUrl: 'https://grainlify.com/logo.png',
    helpUrl: 'https://help.grainlify.com',
    privacyUrl: 'https://grainlify.com/privacy',
    termsUrl: 'https://grainlify.com/terms',
    unsubscribeUrl: 'https://grainlify.com/unsubscribe?token=abc123',
    notificationPreferencesUrl: 'https://grainlify.com/settings/notifications',
    companyName: 'Grainlify',
    companyAddress: '123 Blockchain St, Crypto City, CC 12345',
    currentYear: '2026'
};

const html = template(data);
```

### Email Sending Best Practices

1. **Always send both HTML and plain text versions**:
   ```go
   msg := &mail.Message{
       To:      []string{userEmail},
       Subject: subject,
       HTML:    htmlContent,
       Text:    textContent,
   }
   ```

2. **Set appropriate headers**:
   ```go
   msg.SetHeader("List-Unsubscribe", unsubscribeURL)
   msg.SetHeader("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")
   ```

3. **Use a consistent sender address**:
   ```go
   msg.SetAddressHeader("From", "notifications@grainlify.com", "Grainlify")
   ```

### URL Generation

All URLs should be absolute and include the appropriate protocol:

```go
// Generate unsubscribe URL with unique token
unsubscribeURL := fmt.Sprintf("%s/unsubscribe?token=%s", baseURL, userToken)

// Generate notification preferences URL
prefsURL := fmt.Sprintf("%s/settings/notifications", baseURL)

// Generate transaction URL
txURL := fmt.Sprintf("https://stellar.expert/tx/%s", transactionID)

// Generate bounty URL
bountyURL := fmt.Sprintf("%s/bounties/%s", baseURL, issueNumber)
```

## Edge Cases

### Long Amounts

Handle large numbers gracefully:

```go
// Format large amounts with proper formatting
amount := "1234567.89"
// Display as: "1,234,567.89 XLM"
```

### Missing User Name

Provide a fallback for missing user names:

```go
userName := user.Name
if userName == "" {
    userName = "there" // Fallback to "Hi there,"
}
```

### Long Transaction IDs

Transaction IDs may be very long. Ensure proper wrapping:

```html
<td style="word-break: break-all; font-size: 12px;">
    {{transaction_id}}
</td>
```

### Long Issue Titles

Issue titles may be truncated in the details box:

```go
issueTitle := issue.Title
if len(issueTitle) > 50 {
    issueTitle = issueTitle[:47] + "..."
}
```

### Missing Optional Variables

Handle optional variables gracefully:

```go
// In Go templates, missing variables render as empty strings
// No special handling needed for optional variables
```

## Testing

### Test Data

Use these test values for development:

```go
testPayoutData := PayoutEmailData{
    UserName:              "Test User",
    PayoutAmount:          "100.50",
    TokenSymbol:           "XLM",
    ProjectName:           "Test Project",
    IssueNumber:           "42",
    TransactionID:         "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
    PayoutDate:            "March 30, 2026",
    TransactionURL:        "https://stellar.expert/tx/abc123",
    LogoURL:               "https://grainlify.com/logo.png",
    HelpURL:               "https://help.grainlify.com",
    PrivacyURL:            "https://grainlify.com/privacy",
    TermsURL:              "https://grainlify.com/terms",
    UnsubscribeURL:        "https://grainlify.com/unsubscribe?token=test123",
    NotificationPrefsURL:  "https://grainlify.com/settings/notifications",
    CompanyName:           "Grainlify",
    CompanyAddress:        "123 Blockchain St, Crypto City, CC 12345",
    CurrentYear:           "2026",
}
```

### Email Client Testing

Test templates in these email clients:

- Gmail (Web, iOS, Android)
- Apple Mail (macOS, iOS)
- Outlook (Web, Desktop)
- Yahoo Mail
- Thunderbird

### Dark Mode Testing

Test dark mode rendering:

1. Enable dark mode in email client
2. Verify text remains readable
3. Verify links are visible
4. Verify CTA buttons are visible

### Responsive Testing

Test responsive design:

1. Desktop (600px+ width)
2. Tablet (400-600px width)
3. Mobile (<400px width)

## Compliance

### Unsubscribe Requirements

All transactional emails must include:

1. Clear unsubscribe link in footer
2. Link to notification preferences
3. Company contact information
4. Physical address (if required by jurisdiction)

### CAN-SPAM Compliance

- Include clear sender identification
- Provide valid physical address
- Honor unsubscribe requests within 10 business days
- Include clear subject lines

### GDPR Compliance

- Include privacy policy link
- Provide data processing information
- Allow users to manage preferences

## Dark Mode Limitations

### Known Issues

1. **Background colors**: Some email clients may not respect background colors in dark mode
2. **Image rendering**: Images with transparent backgrounds may not render correctly
3. **Link colors**: Some clients may override link colors

### Mitigation Strategies

1. Use high contrast colors
2. Test in multiple email clients
3. Provide fallback colors
4. Use inline styles for critical elements

## Support

For questions or issues with email templates, contact:

- Email: engineering@grainlify.com
- Slack: #engineering channel
- Documentation: https://docs.grainlify.com/emails
