# HEX TECH

Personal portfolio for Wisdom Boakye, presenting HEX TECH's web development, design, and technology services.

## Run locally

Install Python 3, open a terminal in this folder, and run:

```powershell
python server.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The site uses a small Python standard-library server; no Node packages or other dependencies are required.

The hero portrait currently loads from the reference site's `logo.png`, and portfolio thumbnails load from Unsplash. Update the image `src` values in `fullstack.html` if you want to host your own copies.

The contact form submits to the local server. Messages are appended to `data/contact-messages.jsonl`, which is excluded from Git. Keep that file private because it contains personal contact details.

The server also retains account API endpoints from the former storefront, but the portfolio page does not expose sign-in or registration.

The server binds to localhost for development. Before exposing this site publicly, deploy it behind a production web server with HTTPS, abuse protection, and a suitable data store. The built-in development server is not intended for public production hosting.
