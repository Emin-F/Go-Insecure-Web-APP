-- Create a user table
CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);

-- Insert mock data into the user table
INSERT INTO user (username, password) VALUES ('emin', 'fidan');
INSERT INTO user (username, password) VALUES ('test', 'password');