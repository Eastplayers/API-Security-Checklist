## API Security Checklist

## Authentication

- [x] Use standard authentication instead(recommend Bearer Authentication)
- [x] Use Rate limit in Login to prevent brute force attack
- [x] Use encryption on all sensitive data. (password, user information, ...)

## JWT

- [x] Use a random complicated key (JWT Secret) to make brute-forcing the token very hard (recommend using password generator 1password, Lastpass).
- [x] Don't extract the algorithm from the header. Force the algorithm in the backend (HS256 or RS256). - (deafault is HS256 https://github.com/auth0/node-jsonwebtoken)
- [] Make token expiration (TTL, RTTL) as short as possible. - not yet (need to add refresh token for user)
- [x] Don't store sensitive data in the JWT payload, it can be decoded - (check auth guard)
- [x] Avoid storing too much data. JWT is usually shared in headers and they have a size limit.

## Access

- [x] Api rate limit (Throttling) to avoid DDoS / brute-force attacks.
- [x] Use HTTPS on server side with TLS 1.2+ and secure ciphers to avoid MITM (Man in the Middle Attack).
- [x] Don't create an endpoint with /public
- [x] Turn off directory listings.
- [x] For private APIs, allow access only from whitelisted IPs/hosts. (No private APIs)
- [x] Swagger (Api documentation) page should have basic authentication.
- [x] Turn off Swagger on production environment.
- [] Create admin account with strong password (recommend using password generator 1password, LastPass). (depend on client)

# Authorization

## Role-based (RBAC)

- [x] Validate user token permission scope
- [x] Validate user permission on the frontend side - (frequent call /me api to validate if user is allow to access resource)
- [x] Validate user access permission on the admin dashboard

## Http request

- [ ] Use the proper HTTP method according to the operation: `GET (read)`, `POST (create)`, `PUT/PATCH (replace/update)`, and `DELETE (to delete a record)`, and respond with `405 Method Not Allowed` if the requested method isn't appropriate for the requested resource.
- [ ] Validate `content-type` on request Accept header (Content Negotiation) to allow only your supported format (e.g., `application/xml`, `application/json`, etc.) and respond with `406 Not Acceptable` response if not matched.
- [ ] Validate `content-type` of posted data as you accept (e.g., `application/x-www-form-urlencoded`, `multipart/form-data`, `application/json`, etc.).
- [x] Validate user input to avoid common vulnerabilities (e.g., `XSS`, `SQL-Injection`, `Remote Code Execution`, etc.).
- [x] Don't use any sensitive data (`credentials`, `Passwords`, `security tokens`, or `API keys`) in the URL, but use standard Authorization header.
- [x] Don't return any sensitive data in request response (`reset password tokens`, `password`) in the response.
- [x] Use only server-side encryption.

## Processing

- [x] Check if all the endpoints are protected behind authentication to avoid broken authentication process.
- [x] User own resource ID should be avoided. Use `/me/orders` instead of `/user/654321/orders`.
- [x] Use a CDN for file uploads.
- [x] If you are dealing with huge amount of data, use Workers and Queues to process as much as possible in background and return response fast to avoid HTTP Blocking.
- [x] Do not forget to turn the DEBUG mode OFF.
- [x] Use non-executable stacks when available.
- [x] No console.log

## Source code

- [x] Use a code review process and disregard self-approval.
- [ ] Continuously run security tests (static/dynamic analysis) on your code (recommend using Snyk, SonarQue for code security scanning).
- [ ] Check your dependencies (both software and OS) for known vulnerabilities.
- [ ] Keep track Dependabot report from github to detect package vulnerabilities
- [x] Don't use too old/deprecated package which might have performance or security issue
- [ ] Ensure no text testing, log test on production environment

# Infrastructure Security Checklist

Checklist of the most important security countermeasures when setting up your infrastructure.

---

## Kubernetes

- [x] Create ServiceAccount with limit RBAC for dev

## Database

- [x] Production database only accepts connections from IP whitelisted
- [x] Production database only opens ports for db client connection and closes every unsued ports
- [x] Setup and Document Restore and Backup
- [x] Only Devops keep production credentials in password management (1password, LastPass)
- [ ] Database alerts
- [x] Production database must have authentication setup properly with a strong password

## Image Registry

- [x] Setup private image registry
- [ ] Image scan security turn on if you use Dockerhub

## Controlling Access

- [x] The cloud environment restricted to authorized personnel only
- [x] Enabled two-factor authentication (2FA) for all user accounts
- [x] Strong passwords enforced whenever create or update password
- [x] Access to sensitive data restricted based on job roles and responsibilities

## Network Security

- [x] Firewalls in place to protect the cloud environment
- [ ] Virtual private networks (VPNs) used to secure remote access

## Monitoring

- [x] Use centralized logins for all services and components.
- [x] Use agents to monitor all traffic, errors, requests, and responses.
- [x] Ensure that you aren't logging any sensitive data like credit cards, passwords, PINs, etc.
