// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0

package db

import (
	"github.com/jackc/pgx/v5/pgtype"
)

type UserAccount struct {
	ID       pgtype.UUID
	Name     pgtype.Text
	Email    pgtype.Text
	Password pgtype.Text
}