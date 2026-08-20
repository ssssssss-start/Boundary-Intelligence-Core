"""
Compatibility wrapper.

The project now uses MongoDB for anti-fraud chat history and risk summaries.
Import from app.clients.mongo_history_utils to avoid maintaining two divergent
history implementations.
"""

from app.clients.mongo_history_utils import *  # noqa: F401,F403
