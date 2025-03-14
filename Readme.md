# Summary of _API Sequrity in Action_

**im a person who rogets, I need this summary in first place, that is why I made it, this should warm the memory and roll it with all needed details.**

_i wont be explaining basic staff_

lets digg in

# **Chapter 1:-** _intro_

lots of talk

# **Chapter 2:-** _Secure API Development_

this chapter introduces most basic and common non-identity attacks, things like XXS, Injections, etecetra...

althoug this chapter could be summarized in [owasp top 10](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)

<br>

## SQL Injection

SQL is queries are strings, user inputs are strings, users can inject commands to our api

### preventing _SQL Injection_

#### 1. Use Parameterized Queries (Prepared Statements)

this is using a library or orm that quantize commands instead of passing plain strings

like

```ts
import mysql from "mysql2/promise";

const connection = await mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "password",
  database: "testdb",
});

const [rows] = await connection.execute(
  "SELECT * FROM users WHERE username = ?",
  ["admin"]
);
console.log(rows);
```

#### 2. Use ORM or Query Builders

that is the same concept behind the scenes

```ts
import knex from "knex";

const db = knex({
  client: "pg",
  connection: "postgres://user:password@localhost/testdb",
});

const users = await db("users").where("username", "admin");
console.log(users);
```

#### 3. Validate and Sanitize Input

```ts
import { body, validationResult } from "express-validator";

app.post(
  "/login",
  [
    body("username").isAlphanumeric().trim(),
    body("password").isLength({ min: 6 }),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // Proceed with database query
  }
);
```

#### 4. Use Least Privilege Database Accounts

simply; an api that needs to fetch user names, doesnt need to have the previlage to drop a table for example.

the DB admin is responsible for providing the right previlages to the right services

also each service must be interesten in only one thing, a fetching service mustn't do entire CRUD

<br>

## Input Validation

this is very important practice, it does not only prevent some attacks like DDOS or XXS, It also detects if a user is trying to hack our system. or if there is misSynchrounsation between the client code and server code that the client is giving wrong requests, etcetra.

### how to do input validation

using DTO

```ts
import { IsEmail, IsString, Length, Matches } from "class-validator";

export class RegisterDto {
  @IsString()
  @Length(3)
  username: string;

  @IsEmail()
  email: string;

  @IsString()
  @Length(6)
  @Matches(/\d/, { message: "Password must contain a number" })
  password: string;
}
```

using validation library

```ts
import express from "express";
import Joi from "joi";

const app = express();
app.use(express.json());

const userSchema = Joi.object({
  username: Joi.string().alphanum().min(3).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).pattern(/\d/).required(),
});

app.post("/register", (req, res) => {
  const { error } = userSchema.validate(req.body);
  if (error) {
    return res
      .status(400)
      .json({ errors: error.details.map((err) => err.message) });
  }

  res.send("User registered successfully");
});

app.listen(3000, () => console.log("Server running on port 3000"));
```

etc...

### Evil Regex

> these next sections arent frmo the book

there are some regex bad practices that open the door for DOOS attacks

**Evil regexes typically have:**

- Excessive Backtracking – Patterns with ambiguous quantifiers (e.g., .\*, .+, (?:a|aa)+, etc.) that allow multiple ways to match.

- Catastrophic Complexity – When matching certain inputs, the regex engine tries every possible path, causing exponential execution time.

```ts
const evilRegex = /^(a+)+$/;
const testString = 'aaaaaaaaaaaaaaaaaaaaaaaaa!';
console.log(evilRegex.test(testString));
🔴 Issue: This regex allows overlapping matches of a+, leading to exponential backtracking.
```

### How to Avoid Evil Regex?

#### Use Atomic Grouping ((?>...)) (If Supported)

Some regex engines (like Perl and PCRE) support atomic groups, which prevent backtracking.

for example

```ts
const safeRegex = /^(?>a+)+$/;
```

> Node.js does not support atomic grouping in native JavaScript regex. You may need external regex engines like re2 (discussed below).

```sh
npm install re2
```

```ts
import RE2 from "re2";

const safeRegex = new RE2(/^(a+)+$/);
const testString = "aaaaaaaaaaaaaaaaaaaaaaaaa!";
console.log(safeRegex.test(testString)); // Runs safely without CPU spike
```

#### Avoid Nested Quantifiers ((X+)+)

dont do

```ts
const regex = /^(a+)+$/;
```

instead do

```ts
const safeRegex = /^a+$/;
```

#### use limit quantifiers

dont do

```ts
const regex = /^.*(evil).*/;
```

instead do

```ts
const safeRegex = /^[a-zA-Z0-9 ]{1,100}(evil)[a-zA-Z0-9 ]{1,100}$/;
```

#### Use Timeouts for Regex Execution

```ts
import RE2 from "re2";

const safeRegex = new RE2(/^(a+)+$/, { timeout: 100 });
console.log(safeRegex.test("aaaaaaaaaaaaaaaaaaaaaaaaa!"));
```

### giving safe outputs

they are as important as inputs, do not give details to the client, sometimes it is better to giver false states

## Extras

### **HTTP Security Headers Table**

important heders for security purposes
| Header | Arguments | Description | Default (If Not Set) |
|--------|----------|-------------|----------------------|
| **Content-Security-Policy (CSP)** | Multiple directives (e.g., `default-src 'self'; script-src 'self'`) | Restricts resources like scripts, styles, and media to prevent XSS attacks | No restrictions (browser allows everything) |
| **X-Content-Type-Options** | `nosniff` | Prevents browsers from MIME-type sniffing, reducing exposure to XSS | Browser may sniff content |
| **X-Frame-Options** | `DENY`, `SAMEORIGIN`, `ALLOW-FROM <url>` | Prevents clickjacking by controlling iframe embedding | Can be embedded anywhere |
| **Strict-Transport-Security (HSTS)** | `max-age=<seconds>; includeSubDomains; preload` | Enforces HTTPS by telling browsers to always use secure connections | No forced HTTPS enforcement |
| **Referrer-Policy** | `no-referrer`, `origin`, `strict-origin-when-cross-origin`, etc. | Controls how much referrer info is sent when navigating away | `no-referrer-when-downgrade` |
| **Permissions-Policy** | e.g., `geolocation=(self), camera=()` | Controls access to browser features like camera, microphone, and geolocation | All features may be accessible |
| **Cross-Origin-Opener-Policy (COOP)** | `same-origin`, `same-origin-allow-popups`, `unsafe-none` | Isolates the browsing context to prevent cross-origin attacks | `unsafe-none` |
| **Cross-Origin-Resource-Policy (CORP)** | `same-origin`, `same-site`, `cross-origin` | Controls which origins can fetch resources from your site | No restrictions |
| **Cross-Origin-Embedder-Policy (COEP)** | `require-corp`, `unsafe-none` | Prevents unauthorized cross-origin resource loading | `unsafe-none` |
| **Access-Control-Allow-Origin (CORS)** | `*`, `<origin>`, `null` | Defines allowed origins for cross-origin requests | No cross-origin access allowed |
| **Access-Control-Allow-Methods** | `GET, POST, PUT, DELETE, OPTIONS` | Specifies allowed HTTP methods for cross-origin requests | No cross-origin access allowed |
| **Access-Control-Allow-Headers** | List of headers (e.g., `Content-Type, Authorization`) | Specifies allowed headers in CORS requests | No cross-origin access allowed |
| **Expect-CT** | `max-age=<seconds>; enforce; report-uri=<url>` | Prevents misissued SSL/TLS certificates | No enforcement |
| **X-Permitted-Cross-Domain-Policies** | `none`, `master-only`, `by-content-type`, `by-ftp-filename`, `all` | Controls Adobe Flash and PDF cross-domain policies | `all` (unless blocked by server) |

<br>

**also a reference to all headers [in Mozarilla docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers)**

## rate limiting

this part is from chapter 3

### how to do rate limiting

#### Using express-rate-limit (Best for Simple APIs)

```sh
npm install express-rate-limit
```

### **Basic Usage**

```ts
import express from "express";
import rateLimit from "express-rate-limit";

const app = express();

// Create a rate limiter (100 requests per 15 minutes per IP)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests, please try again later.",
  headers: true, // Show rate limit info in headers
});

// Apply to all routes
app.use(limiter);

app.get("/", (req, res) => {
  res.send("Hello, world!");
});

app.listen(3000, () => console.log("Server running on port 3000"));
```

#### Using `express-rate-limit` with Redis (For Distributed Systems)\*\*

### **Installation**

```sh
npm install express-rate-limit ioredis rate-limit-redis
```

### **Code Example**

```ts
import express from "express";
import rateLimit from "express-rate-limit";
import RedisStore from "rate-limit-redis";
import { createClient } from "redis";

const redisClient = createClient({ url: "redis://localhost:6379" });

redisClient.connect().catch(console.error);

const limiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args: string[]) => redisClient.sendCommand(args),
  }),
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 50, // Limit each IP to 50 requests per 10 minutes
  message: "Rate limit exceeded. Try again later.",
});

const app = express();
app.use(limiter);

app.get("/", (req, res) => {
  res.send("API is working");
});

app.listen(3000, () => console.log("Server running on port 3000"));
```

#### Using `rate-limiter-flexible` (Advanced, More Control)\*\*

### **Installation**

```sh
npm install express rate-limiter-flexible
```

### **In-Memory Rate Limiting**

```ts
import express from "express";
import { RateLimiterMemory } from "rate-limiter-flexible";

const app = express();

// Define rate limiter
const rateLimiter = new RateLimiterMemory({
  points: 10, // 10 requests
  duration: 60, // Per 60 seconds
});

app.use(async (req, res, next) => {
  try {
    await rateLimiter.consume(req.ip); // Consume a point per request
    next();
  } catch {
    res.status(429).send("Too many requests");
  }
});

app.get("/", (req, res) => {
  res.send("API is running");
});

app.listen(3000, () => console.log("Server running on port 3000"));
```

<br>
thats it for chapter 2
```

<br>

# **Chapter 3:-** _Securing the API_

because this book uses a progressive approach for explaining how api security works, some of the chapter's content is not realstic in realworld senarios but the chapter rather focuses on concepts rather than implementations

**the chapter talks about**

- the layers of security

rate limiting => authentication => auditng => authorization

the Idea behind authentication is that there is a content that differs from an authenticated user from unauthenticated user, regardles if the content is public or not

for example, public facebook posts aren't available for unauthenticated users, regardles who the authenticated users are, the content is available for facebook authenticated users, not visitors or bots

also it talks about encryption and hashing

## Authorisation

### ACLs

an ACL is identity based access controle list, it checks if the entity that wants to access a resources is accually listed in the ACL of that resource

<br>

thats it for chapter 3

<br>

# **Chapter 4:-** _Session cookie authentication_

this chapter covers, http cookies, token based auth, CSRF protection
