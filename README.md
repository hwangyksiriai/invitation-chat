# Private creator invitation

An embargo-safe, password-protected draft invitation. The brand name, logo, branded product imagery, and internal planning dates are intentionally absent.

## Run locally

Requires Node.js 20 or newer.

1. Create `.env.local` with `INVITE_PIN` and, optionally, `INVITE_SESSION_SECRET`.
2. Run `npm start`.
3. Open `http://127.0.0.1:3000`.

The `.env.local` file is ignored by Git. Set `INVITE_PIN` and a long random `INVITE_SESSION_SECRET` as private environment variables on the hosting service before deployment. Do not serve `index.html` as a public static file; requests must pass through `server.js` for the access check.

The session cookie expires after eight hours. Five incorrect attempts from an address trigger a 15-minute delay. This invitation is intended for a small recipient list; its four-digit access code should not be treated as protection for highly sensitive material.

## Content awaiting confirmation

- Exact PR BOX contents
- Event date and location
- RSVP destination or contact method
- Approved scope of the founder and product claims

The current page uses the supplied approximate PR BOX value and states that the small group session is available only to some selected invitees, with further details to follow.

