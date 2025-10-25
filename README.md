# LeakChecker — Public Breach Lookup for Email Addresses

LeakChecker is a lightweight single-file PHP app that checks whether an email address appears in known public data breaches using the Have I Been Pwned (HIBP) API.

## Features

- Clean Tailwind UI
- Validates email and queries HIBP v3 `/breachedaccount` endpoint
- Handles common error cases and rate limiting
- Shows breach details (title, domain, dates, record count, exposed data classes)
- No frameworks or build steps required

## Requirements

- PHP 7.4+ with cURL
- A Have I Been Pwned API key

## Setup

1. Place `index.php` on a PHP-capable web server.
2. Provide your HIBP API key via environment variable:

   ```bash
   export HIBP_API_KEY="YOUR_API_KEY"
