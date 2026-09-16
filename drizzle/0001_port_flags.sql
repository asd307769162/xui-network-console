CREATE TABLE port_flags (
  alias TEXT NOT NULL,
  inbound_id INTEGER NOT NULL,
  trusted INTEGER NOT NULL DEFAULT 0,
  observing INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (alias, inbound_id)
);
