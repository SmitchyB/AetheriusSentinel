DROP TABLE IF EXISTS sample_items;

CREATE TABLE sample_items (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('New', 'In Progress', 'Complete'))
);