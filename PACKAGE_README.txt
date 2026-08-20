ANTI-FRAUD PROJECT FULL PACKAGE
===============================

Canonical baseline: DELIVERY_BASELINE.md (delivery date 2026-08-02,
Python 3.11+, Node.js 18+ for mobile/H5 builds, 702 layered evaluation records).

This package contains the backend, web pages, WeChat Mini Program source,
mobile-app source and H5 dist, data, scripts, tests, official video candidate
files, and the local Kokoro TTS model.

Excluded from the package:
- .env and real API keys
- .venv and installed Python dependencies
- mobile-app/node_modules
- model download caches
- runtime logs and Python bytecode caches

First-time setup:
1. Copy .env.example to .env and fill the required API keys.
2. Start MongoDB and Milvus with:
   powershell -ExecutionPolicy Bypass -File scripts/docker-up.ps1
3. Create the Python environment:
   powershell -ExecutionPolicy Bypass -File scripts/setup-delivery.ps1
4. This package includes database_snapshot. Restore it with scripts/restore-delivery-data.ps1 when you need the captured local MongoDB and Milvus data. Treat the snapshot as confidential.
5. Start backend services:
   powershell -ExecutionPolicy Bypass -File scripts/start-delivery-services.ps1

Web pages:
- Import: http://127.0.0.1:8000/import.html
- Chat: http://127.0.0.1:8001/chat.html
- Admin: http://127.0.0.1:8001/admin/review.html

Mobile:
- Open mobile-app in HBuilderX for native App builds.
- The prebuilt H5 files are in mobile-app/dist.
- Open miniprogram in WeChat DevTools for the Mini Program.

See PACKAGE_MANIFEST.json for exact package contents.

