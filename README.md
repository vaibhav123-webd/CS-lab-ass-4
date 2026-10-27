# SecureStudent — Web Security Lab

Academic local lab for the IIIT Allahabad Cyber Security (IT-30001) assignment.

## Scope

This single Express application contains four independent modules:

1. SQL Injection — authentication bypass
2. OS Command Injection — in-band
3. Stored XSS
4. POST-based CSRF

Each module has a deliberately vulnerable implementation and a secured implementation.

## Important safety note

Run this project only on your own machine/local lab. The vulnerable routes exist solely for the course demonstration. Do not expose this application to the public internet or use it against systems you do not own/control.

## Requirements

- Node.js 18+ recommended
- npm

## Run

```bash
npm install
npm start
```

Open:

http://localhost:3000

Demo account:

- Username: `student`
- Password: `student123`

## Suggested group ownership

| Member | Roll No. | Category | Variant |
|---|---|---|---|
| Member 1 | TODO | SQL Injection | Authentication bypass |
| Member 2 | TODO | OS Command Injection | In-band |
| Member 3 | TODO | XSS | Stored XSS |
| Member 4 | TODO | CSRF | POST-based forged action |

## Demonstration structure

For each member:

1. Show the vulnerable code path.
2. Run the locally tested exploit/request.
3. Explain the root cause.
4. Show the implemented mitigation.
5. Run the same request again and show it fails/is rejected.
6. Explain the other mitigation alternatives from the course slides.

## Mitigations implemented in this project

- SQL Injection: parameterized SQL query.
- Command Injection: allow-list validation + argument-based execution without shell interpretation.
- Stored XSS: HTML escaping before rendering in secured mode.
- CSRF: synchronizer token tied to the session.

## Note about the XSS module

The vulnerable comments are intentionally rendered with `innerHTML`; the secured view escapes comment content before insertion. Keep the application local while demonstrating the vulnerable mode.

## Assignment alignment

The assignment requires source code, a group video with each member narrating their own variant, an ownership declaration, and individual viva readiness.
