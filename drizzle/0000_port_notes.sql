CREATE TABLE port_notes (
  alias TEXT NOT NULL,
  inbound_id INTEGER NOT NULL,
  note TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (alias, inbound_id)
);
