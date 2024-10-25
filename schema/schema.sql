
CREATE TABLE user_account (
  id UUID PRIMARY KEY,
  name text,
  email text UNIQUE,
  password text,
  created_at timestamp NOT NULL DEFAULT NOW(),
  updated_at timestamp
);
