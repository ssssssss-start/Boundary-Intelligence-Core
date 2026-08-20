from unittest.mock import patch

from app.clients.mongo_history_utils import get_recent_messages


class FakeCursor:
    def __init__(self, items):
        self.items = items
        self.sort_args = None
        self.limit_value = None

    def sort(self, field, direction):
        self.sort_args = (field, direction)
        return self

    def limit(self, value):
        self.limit_value = value
        return self

    def __iter__(self):
        return iter(self.items)


class FakeChatMessageCollection:
    def __init__(self, cursor):
        self.cursor = cursor
        self.query = None

    def find(self, query):
        self.query = query
        return self.cursor


class FakeMongoTool:
    def __init__(self, cursor):
        self.chat_message = FakeChatMessageCollection(cursor)


def test_get_recent_messages_returns_latest_window_in_chronological_order():
    cursor = FakeCursor([
        {"ts": 5, "text": "newest"},
        {"ts": 4, "text": "newer"},
        {"ts": 3, "text": "older"},
    ])
    tool = FakeMongoTool(cursor)

    with patch("app.clients.mongo_history_utils.get_history_mongo_tool", return_value=tool):
        messages = get_recent_messages("session-1", limit=3)

    assert tool.chat_message.query == {"session_id": "session-1"}
    assert cursor.sort_args == ("ts", -1)
    assert cursor.limit_value == 3
    assert [item["ts"] for item in messages] == [3, 4, 5]
