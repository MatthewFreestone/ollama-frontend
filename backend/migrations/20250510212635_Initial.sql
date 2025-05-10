-- Add migration script here
CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_number INTEGER NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL
        )