-- users
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  nickname TEXT,
  avatar TEXT,
  chat_background TEXT,
  gender TEXT,
  region TEXT,
  signature TEXT,
  invite_code TEXT,
  created_at BIGINT
);

-- friends
CREATE TABLE user_friends (
  user_id INT,
  friend_id INT,
  PRIMARY KEY (user_id, friend_id)
);

-- friend requests
CREATE TABLE friend_requests (
  id SERIAL PRIMARY KEY,
  from_user_id INT,
  to_user_id INT,
  message TEXT,
  status TEXT DEFAULT 'pending',
  timestamp BIGINT
);

-- messages
CREATE TABLE messages (
  id SERIAL PRIMARY KEY,
  from_user_id INT,
  to_id INT,
  to_type TEXT,
  type TEXT,
  content TEXT,
  file_name TEXT,
  duration INT,
  timestamp BIGINT,
  read_at BIGINT
);

-- groups
CREATE TABLE groups (
  id SERIAL PRIMARY KEY,
  name TEXT,
  owner_id INT
);

-- group members
CREATE TABLE group_members (
  group_id INT,
  user_id INT,
  role TEXT
);

-- uploaded files
CREATE TABLE uploaded_files (
  id SERIAL PRIMARY KEY,
  user_id INT,
  filename TEXT,
  original_name TEXT,
  type TEXT
);
