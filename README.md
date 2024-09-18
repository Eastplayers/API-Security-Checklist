# API Security Checklist

Checklist of the most important security countermeasures when designing, testing, and releasing your API.

---

## Authentication

- [ ] Use standard authentication instead (recommend **Bearer Authentication**) (e.g., [JWT](https://jwt.io/)).
- [ ] Use `Rate limit` in Login, Reset Password, Forgot Password to prevent brute force attack
- [ ] Use encryption on all sensitive data. (password, user information, ...)

### JWT (JSON Web Token)

- [ ] Use a random complicated key (`JWT Secret`) to make brute-forcing the token very hard (recommend using password generator 1password, Lastpass).
- [ ] Don't extract the algorithm from the header. Force the algorithm in the backend (`HS256` or `RS256`).
- [ ] Make token expiration (`TTL`, `RTTL`) as short as possible.
- [ ] Don't store sensitive data in the JWT payload, it can be decoded [easily](https://jwt.io/#debugger-io).
- [ ] Avoid storing too much data. JWT is usually shared in headers and they have a size limit.

## Access

- [ ] Api rate limit (Throttling) to avoid DDoS / brute-force attacks.
- [ ] Use HTTPS on server side with TLS 1.2+ and secure ciphers to avoid MITM (Man in the Middle Attack).
- [ ] Don't create an endpoint with `/public`
- [ ] Turn off directory listings.
- [ ] For private APIs, allow access only from whitelisted IPs/hosts.
- [ ] Swagger (Api documentation) page should have basic authentication.
- [ ] Turn off Swagger on production environment.
- [ ] Create admin account with strong password (recommend using password generator 1password, LastPass).

## Authorization

### Role-based (RBAC)

- [ ] Validate user token permission scope
- [ ] Validate user permission on the frontend side
- [ ] Validate user access permission on the admin dashboard

## Http request

- [ ] Use the proper HTTP method according to the operation: `GET (read)`, `POST (create)`, `PUT/PATCH (replace/update)`, and `DELETE (to delete a record)`, and respond with `405 Method Not Allowed` if the requested method isn't appropriate for the requested resource.
- [ ] Validate `content-type` on request Accept header (Content Negotiation) to allow only your supported format (e.g., `application/xml`, `application/json`, etc.) and respond with `406 Not Acceptable` response if not matched.
- [ ] Validate `content-type` of posted data as you accept (e.g., `application/x-www-form-urlencoded`, `multipart/form-data`, `application/json`, etc.).
- [ ] Validate user input to avoid common vulnerabilities (e.g., `XSS`, `SQL-Injection`, `Remote Code Execution`, etc.).
- [ ] Don't use any sensitive data (`credentials`, `Passwords`, `security tokens`, or `API keys`) in the URL, but use standard Authorization header.
- [ ] Don't return any sensitive data in request response (`reset password tokens`, `password`) in the response.
- [ ] Use only server-side encryption.

## Processing

- [ ] Check if all the endpoints are protected behind authentication to avoid broken authentication process.
- [ ] User own resource ID should be avoided. Use `/me/orders` instead of `/user/654321/orders`.
- [ ] Use a CDN for file uploads.
- [ ] If you are dealing with huge amount of data, use Workers and Queues to process as much as possible in background and return response fast to avoid HTTP Blocking.
- [ ] Do not forget to turn the DEBUG mode OFF.
- [ ] Use non-executable stacks when available.
- [ ] No console.log

## Source code

- [ ] Use a code review process and disregard self-approval.
- [ ] Continuously run security tests (static/dynamic analysis) on your code (recommend using Snyk, SonarQue for code security scanning).
- [ ] Check your dependencies (both software and OS) for known vulnerabilities.
- [ ] Keep track Dependabot report from github to detect package vulnerabilities
- [ ] Don't use too old/deprecated package which might have performance or security issue
- [ ] Ensure no text testing, log test on production environment


# Infrastructure Security Checklist

Checklist of the most important security countermeasures when setting up your infrastructure.

---

## Kubernetes

- [ ] Create ServiceAccount with limit RBAC for dev

## Database

- [ ] Production database only accepts connections from IP whitelisted
- [ ] Production database only opens ports for db client connection and closes every unsued ports
- [ ] Setup and Document Restore and Backup
- [ ] Only Devops keep production credentials in password management (1password, LastPass)
- [ ] Database alerts
- [ ] Production database must have authentication setup properly with a strong password

## Image Registry

- [ ] Setup private image registry
- [ ] Image scan security turn on if you use Dockerhub

## Controlling Access

- [ ] The cloud environment restricted to authorized personnel only
- [ ] Enabled two-factor authentication (2FA) for all user accounts
- [ ] Strong passwords enforced whenever create or update password
- [ ] Access to sensitive data restricted based on job roles and responsibilities

## Network Security

- [ ] Firewalls in place to protect the cloud environment
- [ ] Virtual private networks (VPNs) used to secure remote access

## Monitoring

- [ ] Use centralized logins for all services and components.
- [ ] Use agents to monitor all traffic, errors, requests, and responses.
- [ ] Ensure that you aren't logging any sensitive data like credit cards, passwords, PINs, etc.
