# Summary of _API Security in Action_

**I'm a person who forgets, I need this summary in the first place, that is why I made it, this should warm the memory and roll it with all needed details.**

this summary is for people who actually own and read the book, this is just a refresher

follow me on [Linkedin](https://www.linkedin.com/in/kareem-anees-0496b62b3) for more like this

let's dig in

# Part 1: _Foundations_

# **Chapter 1:-** _intro_

lots of talk

anyways, I suggest implementing the [owasp top 10](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html) on every API

also watching this lecture about HTTP cookie by Hussein Nasser on [youtube](https://www.youtube.com/watch?v=sovAIX4doOE&pp=ygUjZG91YmxlIHN1Ym1pdCBjb29raWUgY3NyZiBleHBsYWluZWQ%3D)

also reading about HTTP [from MDN web docs](https://developer.mozilla.org/en-US/docs/Web/HTTP)

also rereading this Readme progressively

also implementing this security model

![alt text](image-3.png)

# **Chapter 2:-** _Secure API Development_

this chapter introduces most basic and common non-identity attacks, things like XSS, Injections, etcetera...

although this chapter could be summarized in [owasp top 10](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)

<br>

## SQL Injection

SQL is queries are strings, user inputs are strings, users can inject commands to our API

### preventing _SQL Injection_

#### 1. Use Parameterized Queries (Prepared Statements)

this is using a library or ORM that parameterizes commands instead of passing plain strings

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

simply; an API that needs to fetch user names, doesn't need to have the privilege to drop a table for example.

the DB admin is responsible for providing the right privileges to the right services

also each service must be interested in only one thing, a fetching service mustn't do entire CRUD

<br>

## Input Validation

this is very important practice, it does not only prevent some attacks like DDOS or XSS, It also detects if a user is trying to hack our system. or if there is mis-synchronization between the client code and server code that the client is giving wrong requests, etcetera.

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

> these next sections aren't from the book

there are some regex bad practices that open the door for DoS attacks

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

# Part 2: _Authentication_

# **Chapter 4:-** _Session cookie authentication_

this chapter covers, http cookies, token based auth, CSRF protection

**Token based aouthentication**: instead of asking the user to type credentials manually, why not to give them something for a duration that tell "hey there im user123"

the whole next 3 chapters only talk about this

## Session cookies

as it's name suggests, it is a session cookie, it is meant to be used for the session, once the session ends, the cookie die

> like when trying to delete github repo for the rist time and later at the same moment, the first time requires a login, then no login is required untill the browser is closed

> the concept of session is not always cookie session, it could be in the BOM or binded with the IP or just dynamic, but cookies offer a combination of thome benifets

this is how it works

![alt text](image.png)

### creating session cookies

also the author states that the token is stored on the sserver so the server checks it, and the expiry date is put in the session

the following code violates this, it just sends a cookie and authenticated with it

```ts
//@ts-nocheck

const users = [{ id: 1, username: "admin", password: "password123" }];
import express, {
  Request as ExpressRequest,
  Response,
  RequestHandler,
} from "express";
import session from "express-session";
import cors from "cors";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import path from "path";

dotenv.config();
const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "http://localhost:3000", // React frontend URL
    credentials: true, // Allows sending cookies
  })
);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret", // Use env variables in production
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // Prevents XSS attacks
      secure: false, // Set to `true` in production with HTTPS
      sameSite: "lax", // Helps prevent CSRF
    },
  })
);

import { Session } from "express-session";

app.post("/api/login", (req: Request, res: Response) => {
  const { username, password } = req.body;
  const user = users.find(
    (u) => u.username === username && u.password === password
  );
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  req.session.user = { id: user.id, username: user.username };

  res.json({ message: "Login successful" });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ message: "Logged out" });
  });
});

app.use(express.static(path.join(__dirname, "..", "..", "/frontend", "/dist"))); // For Vite
app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "..", "..", "/frontend", "/dist", "index.html")
  ); // For Vite
});

//@ts-ignore
app.get("/api/profile", (req, res) => {
  //@ts-ignore

  if (!req.session.user)
    return res.status(401).json({ message: "Unauthorized" });
  //@ts-ignore

  res.json({ user: req.session.user });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
```

the fontend

```ts
//@ts-nocheck

import { useState, useEffect } from "react";
import axios from "axios";

const API = axios.create({
  baseURL: "http://localhost:3000/api",
  withCredentials: true, // Allow session cookies
});

export default function App() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [user, setUser] = useState<{ username: string } | null>(null);

  // Fetch profile on load
  useEffect(() => {
    API.get("/profile")
      .then((res) => setUser(res.data.user))
      .catch(() => setUser(null));
  }, []);

  // Handle login
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await API.post("/login", { username, password });
      const res = await API.get("/profile"); // Fetch user after login
      setUser(res.data.user);
    } catch (error) {
      alert("Login failed");
    }
  };

  return (
    <div style={{ textAlign: "center", marginTop: "50px" }}>
      {!user ? (
        <form onSubmit={handleLogin}>
          <h2>Login</h2>
          <input
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button type="submit">Login</button>
        </form>
      ) : (
        <h2>Welcome, {user.username}!</h2>
      )}
    </div>
  );
}
```

the code is messy and chat-gpt generated but it works, if you want to try it run

```sh
cd backend

npm i express express-session cors cookie-parser dotenv
```

```sh
cd frontend

npm create vite@latest my-app --template react-ts

npm install axios react-router-dom

```

thats it for creating the session cookies

### session fixation attacks

so, I have a cookie, someone can steal it and pretend to be me, what to do?

this is how it is done

![alt text](image-1.png)

so a session fixation attack occurs when an API fails to generate a new
session token after a user has authenticated. The attacker captures a session
token from loading the site on their own device and then injects that token

#### how to protect againest session fixation attacks

when it comes to browsers features, it is on the browser, so browsers invinted attributes

| Attribute             | Description                                                    | Purpose                                  |
| --------------------- | -------------------------------------------------------------- | ---------------------------------------- |
| **Secure**            | Sends the cookie only over HTTPS.                              | Prevents exposure over unencrypted HTTP. |
| **HttpOnly**          | Restricts access to the cookie from JavaScript.                | Mitigates XSS attacks.                   |
| **SameSite**          | Controls cross-site cookie behavior (`Strict`, `Lax`, `None`). | Helps prevent CSRF attacks.              |
| **Domain**            | Specifies the domain for which the cookie is valid.            | Limits scope of the cookie.              |
| **Path**              | Restricts the cookie to a specific path.                       | Defines where the cookie is accessible.  |
| **Expires / Max-Age** | Sets the cookie expiration time.                               | Controls how long the cookie persists.   |
| **Partitioned**       | Ensures cookie isolation across sites.                         | Prevents cross-site tracking.            |

### Persistent cookies VS Session cookies

the previous code example is not really a session cookie, because the browser did not get rid of the cookie when the window is closed

here is the book definetion for _Persistent cookies VS Session cookies_:

> A cookie with an explicit Expires or Max-Age attribute is known as a persistent cookie
> and will be permanently stored by the browser until the expiry time is reached, even
> if the browser is restarted. Cookies without these attributes are known as session
> cookies (even if they have nothing to do with a session token) and are deleted when
> the browser window or tab is closed. You should avoid adding the Max-Age or Expires
> attributes to your authentication session cookies so that the user is effectively
> logged out when they close their browser tab. This is particularly important on shared
> devices, such as public terminals or tablets that might be used by many different people. Some browsers will now restore tabs and session cookies when the browser is
> restarted though, so you should always enforce a maximum session time on the
> server rather than relying on the browser to delete cookies appropriately. You should
> also consider implementing a maximum idle time, so that the cookie becomes invalid
> if it has not been used for three minutes or so. Many session cookie frameworks
> implement these checks for you.
> Persistent cookies can be useful during the login process as a "Remember Me"
> option to avoid the user having to type in their username manually, or even to automatically log the user in for low-risk operations. This should only be done if trust in
> the device and the user can be established by other means, such as looking at the
> location, time of day, and other attributes that are typical for that user. If anything
> looks out of the ordinary, then a full authentication process should be triggered. Selfcontained tokens such as JSON Web Tokens (see chapter 6) can be useful for implementing persistent cookies without storing long-lived state on the server.

## CSRF

**Cross-site request forgery (CSRF, pronounced "sea-surf") occurs
when an attacker makes a cross-origin request to your API and the browser
sends cookies along with the request. The request is processed as if it was genuine unless extra checks are made to prevent these requests.**

![alt text](image-2.png)

> TIP An important part of protecting your API from CSRF attacks is to ensure
> that you never perform actions that alter state on the server or have other
> real-world effects in response to GET requests. GET requests are almost
> always allowed by browsers and most CSRF defenses assume that they are safe.

### protection againest CSRF

#### using **SameSite**

A SameSite cookie will only be sent on requests that originate
from the same domain that originally set the cookie.

![alt text](image-4.png)

To mark a cookie as SameSite, you can add either `SameSite=lax` or `SameSite=strict` on
the Set-Cookie header

> Recent versions of Chrome have started marking cookies as SameSite=lax by default.1
> Other major browsers have announced intentions to
> follow suit. You can opt out of this behavior by explicitly adding a new SameSite=none attribute to your cookies, but only if they are also Secure. Unfortunately, this new attribute is not compatible with all browsers.

#### using **Double Submitt Cookie**

So instead of the server managing everything and rely on the browser blindly, lets make the frontend do somework

the server will send a CSRF toke, the frontend should resend it but not automatically like cookies

to clear confusion, read this post on [stackoverflow](https://stackoverflow.com/questions/65854195/csrf-double-submit-cookie-is-basically-not-secure) on how this actuallly work

a high level view of the flow

![alt text](image-5.png)

![alt text](image-6.png)

**This amazing [youtube video](https://www.youtube.com/watch?v=80S8h5hEwTY) explaines how to implement this**

<br>

thats it for this chapter

# **Chapter 5:-** _Modern token-based authentication_

this chapter talks abour CORS and some cool browser's features

Here's the explanation in Markdown format:

## Preflight Request in CORS

A **preflight request** is an **HTTP OPTIONS** request sent by the browser **before** making an actual cross-origin request. It checks whether the server allows the actual request based on the HTTP method and headers.

### Why Is a Preflight Request Needed?

A preflight request occurs when:

- The request uses HTTP methods other than **GET**, **HEAD**, or **POST**.
- The request includes custom headers (e.g., `Authorization`, `X-Requested-With`).
- The request's `Content-Type` is something other than:
  - `application/x-www-form-urlencoded`
  - `multipart/form-data`
  - `text/plain`

### How a Preflight Request Works

1. The browser sends an **OPTIONS** request to the server with:

   - `Access-Control-Request-Method`: The actual HTTP method intended for the request.
   - `Access-Control-Request-Headers`: Any custom headers the actual request will use.
   - `Origin`: The domain of the request's origin.

2. The server responds with allowed methods, headers, and origins using CORS headers:

   - `Access-Control-Allow-Origin`: Allowed origins.
   - `Access-Control-Allow-Methods`: Allowed HTTP methods.
   - `Access-Control-Allow-Headers`: Allowed request headers.

3. If the preflight request succeeds, the browser proceeds with the actual request.

### Example

#### **Preflight Request (Sent by Browser)**

```http
OPTIONS /api/data HTTP/1.1
Host: api.example.com
Origin: https://myapp.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type, Authorization
```

#### **Preflight Response (From Server)**

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://myapp.com
Access-Control-Allow-Methods: GET, POST, PUT
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 86400
```

The `Access-Control-Max-Age` header tells the browser how long it can cache this preflight response.

![alt text](image-7.png)

![alt text](image-8.png)

![alt text](image-9.png)

### CORS Headers Table

| Header                               | Description                                                                         | Example Value                             |
| ------------------------------------ | ----------------------------------------------------------------------------------- | ----------------------------------------- |
| **Access-Control-Allow-Origin**      | Specifies which origins are allowed to access the resource.                         | `*` (any origin) or `https://example.com` |
| **Access-Control-Allow-Methods**     | Lists the HTTP methods allowed when accessing the resource.                         | `GET, POST, PUT, DELETE`                  |
| **Access-Control-Allow-Headers**     | Specifies which headers can be used in the actual request.                          | `Content-Type, Authorization`             |
| **Access-Control-Allow-Credentials** | Indicates whether cookies and credentials can be included in cross-origin requests. | `true` or `false`                         |
| **Access-Control-Expose-Headers**    | Specifies which headers the browser can access from the response.                   | `X-Custom-Header, Authorization`          |
| **Access-Control-Max-Age**           | Defines how long (in seconds) the preflight response can be cached.                 | `86400` (1 day)                           |
| **Access-Control-Request-Method**    | Sent by the browser in a preflight request to indicate the desired HTTP method.     | `POST`                                    |
| **Access-Control-Request-Headers**   | Sent by the browser in a preflight request to list the headers it wants to send.    | `Content-Type, Authorization`             |
| **Origin**                           | Indicates the origin of the request. Sent by the browser.                           | `https://myapp.com`                       |

#### Configureing CORS in Express.js app

```ts
import express from "express";
import cors from "cors";

const app = express();

// Allow requests from your SPA domain
const corsOptions = {
  origin: "https://your-spa-domain.com", // Replace with your actual frontend domain
  methods: ["GET", "POST", "PUT", "DELETE"], // Allowed HTTP methods
  allowedHeaders: ["Content-Type", "Authorization"], // Allowed request headers
  credentials: true, // Allow cookies and authentication headers
};

app.use(cors(corsOptions));

// Example route
app.get("/api/data", (req, res) => {
  res.json({ message: "CORS is working!" });
});

// Start server
app.listen(5000, () => {
  console.log("Server running on port 5000");
});
```

to set multiple origins

```ts
const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = ["https://spa-dev.com", "https://spa-prod.com"];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
};
```

> SameSite cookies, described in chapter 4, are fundamentally incompatible with CORS.
> If a cookie is marked as SameSite, then it will not be sent on cross-site requests
> regardless of any CORS policy and the Access-Control-Allow-Credentials header is
> ignored. An exception is made for origins that are sub-domains of the same site; for
> example, www.example.com can still send requests to api.example.com, but genuine
> cross-site requests to different registerable domains are disallowed. If you need to
> allow cross-site requests with cookies, then you should not use SameSite cookies.
> A complication came in October 2019, when Google announced that its Chrome web
> browser would start marking all cookies as SameSite=lax by default with the release
> of Chrome 80 in February 2020. (At the time of writing the rollout of this change has
> been temporarily paused due to the COVID-19 coronavirus pandemic.) If you wish to
> use cross-site cookies you must now explicitly opt-out of SameSite protections by
> adding the SameSite=none and Secure attributes to those cookies, but this can
> cause problems in some web browsers (see https://www.chromium.org/updates/
> same-site/incompatible-clients). Google, Apple, and Mozilla are all becoming more
> aggressive in blocking cross-site cookies to prevent tracking and other security or privacy issues. It's clear that the future of cookies will be restricted to HTTP requests
> within the same site and that alternative approaches, such as those discussed in the
> rest of this chapter, must be used for all other cases.

## the rest

**the rest of this chapter disusses the implementation of the "statefull" tokens storage on the server and talks about the possibility of storing the tokens in the BOM instead of the Dom which reduse CSRF risk but actually increase the risk of XSS, Maybe an extra work would be a combination of these mechanisms (by having anti-CSRF token that actes on client-side level)**

# **Chapter 6:-** _Self-contained tokens and JWTs_

The idea behind stateless tokens is simple. Rather than store the token state in the
database, you can instead encode that state directly into the token ID and send it to
the client. For example, you could serialize the token fields into a JSON object, which
you then Base64url-encode to create a string that you can use as the token ID. When
the token is presented back to the API, you then simply decode the token and parse
the JSON to recover the attributes of the session.

![alt text](image-10.png)

## JWT

> The JWT standards zoo
> While JWT itself is just one specification (https://tools.ietf.org/html/rfc7519), it
> builds on a collection of standards collectively known as JSON Object Signing and
> Encryption (JOSE). JOSE itself consists of several related standards:
>  JSON Web Signing (JWS, https://tools.ietf.org/html/rfc7515) defines how
> JSON objects can be authenticated with HMAC and digital signatures.
>  JSON Web Encryption (JWE, https://tools.ietf.org/html/rfc7516) defines how
> to encrypt JSON objects.
>  JSON Web Key (JWK, https://tools.ietf.org/html/rfc7517) describes a standard format for cryptographic keys and related metadata in JSON.
>  JSON Web Algorithms (JWA, https://tools.ietf.org/html/rfc7518) then specifies signing and encryption algorithms to be used.
> JOSE has been extended over the years by new specifications to add new algorithms
> and options. It is common to use JWT to refer to the whole collection of specifications, although there are uses of JOSE beyond JWTs.

I will not talk about JWTs, Just visit it's site or reread the chapter

in summary, JWT provides good specifications for self contained tokens, instead of creating a normal token with an ID and then statefully save it, just encrypt a JWT and put needed data inside it

<br>

that's it for chapter 6

<br>

# Part 3: _Authorization_

# **Chapter 7:-** _OAuth2 and OpenID Connect_

Chapter 7 starts by taking a look at delegated authorization with OAuth2. In
this chapter, you'll learn the difference between discretionary and mandatory
access control and how to protect APIs with OAuth2 scopes.

**OAuth is very good for confidential clients and APIs, most public clients doesn't really need to use OAuth**

## Scoped Tokens

insteaad of giving some user or some external third party the e-mail and password with good sake and love trust for doing only specific action, let's instead give them a token that only allow them to do only this action

> A scoped token limits the operations that can be performed with
> that token. The set of operations that are allowed is known as the scope of the
> token. The scope of a token is specified by one or more scope labels, which
> are often referred to collectively as scopes.

### Scopes vs Permissions

At first glance, it may seem that scopes and permissions are very similar, but there is a
distinction in what they are used for, as shown in figure 7.2. Typically, an API is owned
and operated by a central authority such as a company or an organization. Who can
access the API and what they are allowed to do is controlled entirely by the central
authority. This is an example of mandatory access control, because the users have no con-
trol over their own permissions or those of other users. On the other hand, when a
user delegates some of their access to a third-party app or service, that is known as dis-
cretionary access control, because it's up to the user how much of their access to grant to
the third party. OAuth scopes are fundamentally about discretionary access control,
while traditional permissions (which you implemented using ACLs in chapter 3) can
be used for mandatory access control.

![alt text](image-11.png)

> With mandatory access control (MAC), user permissions are set and
> enforced by a central authority and cannot be granted by users themselves.
> With discretionary access control (DAC), users can delegate some of their permis-
> sions to other users. OAuth2 allows discretionary access control, also known
> as delegated authorization.

> permissions for MAC are covered in chapter 8. OAuth scopes provide a way to layer
> DAC on top of an existing MAC security layer.

> The delegated authorization in OAuth is about users delegating their
> authority to clients, such as mobile apps. The User Managed Access (UMA)
> extension of OAuth2 allows users to delegate access to other users.

## Introducing OAuth2

> The tokens that an
> application uses to access an API are known as access tokens in OAuth2

![alt text](image-12.png)

---

**Some conventions for the rest of the chapter**

- The authorization server (AS) authenticates the user and issues tokens to clients.

- The user is known as the resource owner (RO), because it's typically their resources (documents, photos, and so on) that the third-party app is trying to access. This term is not always accurate, but it has stuck now.

- The third-party app or service is known as the client.

- The API that hosts the user's resources is known as the resource server (RS).

- public clients are applications that run entirely within a user's own device, such as a mobile app or JavaScript client running in a browser The client is completely under the user's control.

- Confidential clients run in a protected web server or other secure location that is not under a user's direct control

> A confidential client uses client credentials to authenticate to the
> AS. Usually, this is a long random password known as a client secret, but more
> secure forms of authentication can be used, including JWTs and TLS client

### Authorization grants

> Before a client can ask for an access token it must first register with the AS and obtain
> a unique client ID

- In the Authorization Code grant, the client first uses a web browser to navigate to a
  dedicated authorization endpoint on the AS, indicating which scopes it requires.

- The AS then authenticates the user directly in the browser and asks for consent
  for the client access.

- If the user agrees then the AS generates an authorization
  code and gives it to the client to exchange for an access token at the token end-
  point. The authorization code grant is covered in more detail in the next section.

- The Client Credentials grant allows the client to obtain an access token using its
  own credentials, with no user involved at all. This grant can be useful in some
  microservice communications patterns discussed in chapter 11.

- There are several additional grant types for more specific situations, such as the
  device authorization grant (also known as device flow) for devices without any
  direct means of user interaction.

- There is no registry of defined grant types, but
  websites such as https://oauth.net/2/grant-types/ list the most commonly used
  types. The device authorization grant is covered in chapter 13.

- OAuth2 grants
  are extensible, so new grant types can be added when one of the existing grants
  doesn't fit.

### How Oauth works

t, the client first redirects the user's web browser to the
authorization endpoint at the AS, as shown in figure

![alt text](image-13.png)

![alt text](image-14.png)

the client should genetate a unique key so the AS redirects with this key to avoid open redirect vulnerability

> An open redirect vulnerability is when a server can be tricked into
> redirecting a web browser to a URI under the attacker's control. This can be
> used for phishing because it initially looks like the user is going to a trusted
> site, only to be redirected to the attacker. You should require all redirect URIs
> to be pre-registered by trusted clients rather than redirecting to any URI pro-
> vided in a request.

## OpenID connect (OIDC)

**OAuth can provide basic SSO functionality, but the primary focus is on delegated third-party access to APIs rather than user identity or session management. The OpenID Connect (OIDC) suite of standards (https://openid.net/developers/specs/) extend OAuth2 with several features**

A standard way to retrieve identity information about a user, such as their name,
email address, postal address, and telephone number. The client can access a
UserInfo endpoint to retrieve identity claims as JSON using an OAuth2 access
token with standard OIDC scopes.

A way for the client to request that the user is authenticated even if they have an
existing session, and to ask for them to be authenticated in a particular way,
such as with two-factor authentication. While obtaining an OAuth2 access token
may involve user authentication, it's not guaranteed that the user was even pres-
ent when the token was issued or how recently they logged in. OAuth2 is primar-
ily a delegated access protocol, whereas OIDC provides a full authentication
protocol. If the client needs to positively authenticate a user, then OIDC should
be used.

Extensions for session management and logout, allowing clients to be notified
when a user logs out of their session at the AS, enabling the user to log out of all
clients at once (known as single logout).

> In OIDC, the AS and RS are combined into a single entity known
> as an OpenID Provider (OP). The client is known as a Relying Party (RP).

## Summary of lecture pn Oauth2 by OKTA

---

**A nice video on [youtube](https://www.youtube.com/watch?v=996OiexHze0&t=110s) that explains the thing**, a combination of resources is much better than singularity chains

---

**Oauth 2.0 termonologies**

- **_Resource owner_ (RO)** is the user itself that owns the resource

- **_Client_** is the entity that ant to access the resource

- **_Authorization Server_ (AS)** is the server that takes auth requests, generates, auth codes and tokens

- **_Resource Server_ (RS)** this is the server that trust the token that is issued by the AS

- **Access Token** the token mentioned above

- **Redirect URL** redirect URL :)

- **Authorization grant** a prove that the user has consented to give a permission (more of an implementation thing)

---

a nice snippet from that video

![alt text](image-15.png)

another way is like
![alt text](image-16.png)

in the first image; a more secure approach that that relies on the backend more

> OAuth is made for delegated authorization and resources accessing, not for mandatory authorization and not for authentication

**another approach**

![alt text](image-20.png)

![alt text](image-21.png)

### openid connect

a framework above Oauth for authentication

![alt text](image-18.png)
![alt text](image-19.png)

most common example is next-auth with google provider

---

thats it for chapter 7

---

# **Chapter 8:-** _Identity based access control_

**in Identity based access control** we give users permission based on who they are

## Users and groups

users can belong to groups, groups can belong to other groups

a group carries a set of permissions

**therfor it is called subject**

![alt text](image-22.png)

## Role based access control

we give users roles, roles carry permission

like AWS policies, they have permission, and I can attach policies to subjects (users or group of users)

![alt text](image-23.png)

## Attribute based access control

**example problem that ABAC solves:** Consider the call center agent example from section 8.2.4. As well as
preventing the agent from accessing customer records outside of their contracted
working hours, you might also want to prevent them accessing those records if they
are not actually on a call with that customer. Allowing each agent to access all cus-
tomer records during their working hours is still more authority than they really need
to get their job done, violating the principle of least privilege. It may be that you can
determine which customer the call agent is talking to from their phone number
(caller ID), or perhaps the customer enters an account number using the keypad
before they are connected to an agent. You'd like to only allow the agent access to just
that customer's file for the duration of the call, perhaps allowing five minutes after-
ward for them to finishing writing any notes.

![alt text](image-24.png)

whenever a client tries to do anything it must give attributes of the action

**these attributes can be**

- _Attributes about the subject_ the subject that is making the request

- _Attributes about the resource_ the resource that is owned by the resource owner

- _Attributes about the action_ what action are we performing

the client must provide these attributes, then the Server authorize the request based on these attributes

# **Chapter 9:-** _capability based access control_

what I have been doing in chapter 7 is giving users a token, only my server can decrypt and read the token. what capability based control is; it to give authorize token instead of users, this allow sharing resources with many users regardless of what roles or groups they belong to, or even to third parties

---

<br>

---

<br>

---

<br>

---

<br>

---

<br>

---

<br>

---

<br>

# THE END

i wont pu the rest of this book because it talks about microservices and imbedded that i will explain independently

If you like this, see give my [Linkedin Profile](https://www.linkedin.com/in/kareem-anees-0496b62b3) a visit
