# Viva Notes

## SQL Injection
Root cause: untrusted username/password values are concatenated into an SQL statement in the vulnerable endpoint.

Implemented mitigation: parameterized query (`?` placeholders).

Other mitigations from the assignment:
- Input validation with allow-lists
- Least-privilege database accounts
- Safe errors

## OS Command Injection
Root cause: user-controlled input is incorporated into a shell command string in the vulnerable endpoint.

Implemented mitigation: strict allow-list validation plus argument-based execution without shell interpretation.

Other mitigations:
- Avoid the shell
- Parameterized execution with an argument vector
- Allow-list validation
- Least privilege

## Stored XSS
Root cause: stored user input is rendered as HTML rather than treated as text.

Implemented mitigation: context-appropriate HTML escaping before rendering.

Other mitigations:
- Framework auto-escaping
- Sanitizer for rich HTML
- Content Security Policy
- HttpOnly cookies
- Safe DOM sinks

## POST CSRF
Root cause: the vulnerable state-changing POST accepts the request without proof that it originated from the intended application flow.

Implemented mitigation: synchronizer token stored in the session and required by the secured endpoint.

Other mitigations:
- SameSite cookies
- Re-authentication for sensitive actions
- Avoid state-changing GET requests

## Video script template
"First I will show the vulnerable implementation. This is the exact code path responsible. Now I send my locally tested payload/request and the attack succeeds. The root cause is ____. I then apply ____. Finally I send the same request again; this time it is rejected/does not produce the unintended effect."
