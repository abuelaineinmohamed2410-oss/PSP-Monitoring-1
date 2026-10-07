# PSP Monitoring Management System (server build)
Node/Express API + SQLite + the web UI. Roles, hashed passwords (bcrypt), signed httpOnly session cookie,
server-side authorization, supervisor data isolation, immutable submitted records, server-side scoring and audit log.

## Run
    JWT_SECRET=<24+ random chars> ADMIN_PASSWORD=<strong pw> docker compose up -d --build
Open http://localhost:3000, sign in as `admin`, create supervisors/QA under Agents > Add user.
Behind HTTPS set COOKIE_SECURE=1. Back up the `psp-data` volume.

## Not included yet
PostgreSQL (data layer is the get/all/put/del helpers in server.js), exact DOCX-to-PDF Annex printing,
original Annex file storage, password reset, SSO.
