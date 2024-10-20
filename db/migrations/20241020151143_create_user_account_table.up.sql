
CREATE TABLE user_account (
  id UUID PRIMARY KEY,
  name text,
  email text UNIQUE,
  password text
);
