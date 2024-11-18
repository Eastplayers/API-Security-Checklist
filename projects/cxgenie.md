# API Security Checklist

Checklist of the most important security countermeasures when designing, testing, and releasing your API.

---

## Authentication

- [x] Use standard authentication instead (recommend **Bearer Authentication**) (e.g., [JWT](https://jwt.io/)).
- [ ] Use `Rate limit` in Login to prevent brute force attack
- [x] Use encryption on all sensitive data. (password, user information, ...)

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
- [x] Validate user permission on the frontend side
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

## Source code

- [ ] Check your dependencies (both software and OS) for known vulnerabilities.
- [ ] Don't use too old/deprecated package which might have performance or security issue.
- [ ] ~~Keep track Dependabot report from github to detect package vulnerabilities.~~ **Will need to discuss with client because it's a paid feature**
- [ ] ~~Continuously run security tests (static/dynamic analysis) on your code (recommend using Snyk, SonarQue for code security scanning).~~ **Will need to discuss with client because it's a paid feature**

# Infrastructure Security Checklist

Checklist of the most important security countermeasures when setting up your infrastructure.

---

## Kubernetes

- [ ] ~~Create ServiceAccount with limit RBAC for dev~~ **We don't have dev account in K8s cluster**
- [ ] Only Devops has Cluster Admin permisison (k8s config)
- [ ] Sensitive config should be stored as Secret
- [ ] Review helm chart before helm install (verify docker image, sidecar container, owner)

## Database

- [ ] Production database only accepts connections from IP whitelisted
- [ ] Production database only opens ports for db client connection and closes every unused ports
- [ ] Setup and Document Restore and Backup
- [ ] Only DevOps keep production credentials in password management (1password, LastPass)
- [ ] Production database must have authentication setup properly with a strong password

## Image Registry

- [ ] Setup private image registry
- [ ] ~~Image scan security turn on if you use Dockerhub~~ **Will need to discuss with client because it's a paid feature**

## Controlling Access

- [ ] The cloud environment is restricted to authorized personnel only
- [ ] Enabled two-factor authentication (2FA) for all user accounts
- [ ] Strong passwords enforced whenever creating or update a password
- [ ] Access to sensitive data restricted based on job roles and responsibilities

## Network Security

- [ ] Firewalls in place to protect the cloud environment
- [ ] Authentication between cross-service communication
- [ ] ~~Virtual private networks (VPNs) used to secure remote access~~ **No setup because we don't have remote access to our cluster**

## Monitoring

- [ ] Use centralized logins for all services and components.
- [ ] Use agents to monitor all traffic, errors, requests, and responses.
- [ ] Ensure that you aren't logging any sensitive data like credit cards, passwords, PINs, etc.

--- 
Explanations:

- [ ] we have reviewed

~~line-stroke~~ we haven't implemented

**bold** reason why we haven't implemented it
