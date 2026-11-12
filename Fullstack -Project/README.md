# HEX TECH

Personal portfolio for Wisdom Boakye, presenting HEX TECH's web development, design, and technology services.

## Run locally

Install Python 3, open a terminal in this folder, and run:

```powershell
python server.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). Local development uses Python's standard library. The Render deployment uses Waitress as its production WSGI server.

The hero portrait is included locally as `wisdom.png` and served by the development server. Portfolio thumbnails load from Unsplash. Update the image `src` values in `fullstack.html` if you want to use different images.

Contact-form submissions are stored in the local SQLite database at `data/wisdom-market.sqlite3`, which is excluded from Git. On server startup, entries in the legacy `data/contact-messages.jsonl` file are imported into the inbox without duplicating previously imported messages. The original JSONL file is preserved as a backup.

## Admin inbox

Stop any already-running copy of the server first. In PowerShell, set an admin password and start the server from this folder:

```powershell
$env:WISDOM_ADMIN_PASSWORD = "your-long-unique-password"
python server.py
```

Keep the server running in that terminal, then open [http://127.0.0.1:8000/admin](http://127.0.0.1:8000/admin). The inbox lets you view and search messages, select messages to permanently delete, open a Gmail draft or email reply, and contact senders through WhatsApp, SMS, or a call when they provided a phone number. Visitors can optionally provide their phone number; include the country code for WhatsApp.

The admin password is read from the environment and is never stored in the source files. The PowerShell environment variable lasts only for that terminal session, so set it again whenever you start a new one. Admin sign-ins expire after eight hours. For an HTTPS deployment behind a production server, also set `WISDOM_COOKIE_SECURE=1`. Do not expose the built-in development server directly to the internet.

## Deploy to Render

The repository includes a Render Blueprint at `render.yaml`. To publish the site:

1. Push the repository, including `render.yaml` and the `Fullstack -Project` folder, to GitHub.
2. In Render, choose **New → Blueprint**, connect the GitHub repository, and select the `render.yaml` Blueprint.
3. Enter a new, private value for `WISDOM_ADMIN_PASSWORD` when prompted, then confirm the service creation.
4. After the deploy succeeds, open the public `onrender.com` URL shown in the Render dashboard. The inbox is at that URL followed by `/admin`.

The Blueprint uses a paid Render web-service plan and a persistent disk mounted at `/var/data`. The disk keeps the SQLite inbox across deploys and restarts. Keep a single service instance when using this SQLite setup. The environment file and local `data/` files are not included in Git; any existing messages stored only on your computer will need to be migrated separately.

The server also retains account API endpoints from the former storefront, but the portfolio page does not expose sign-in or registration.

The server binds to localhost for development. Before exposing this site publicly, deploy it behind a production web server with HTTPS, abuse protection, and a suitable data store. The built-in development server is not intended for public production hosting.
