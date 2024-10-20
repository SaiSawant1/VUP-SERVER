-- name: GetAllUsers :one
SELECT * FROM user_account;

-- name: CreateUser :one
INSERT INTO user_account (
  id, name, email, password
) VALUES (
  $1, $2, $3, $4
)
RETURNING *;


-- name: GetUserByEmail :one
Select * from user_account
WHERE email = $1;
