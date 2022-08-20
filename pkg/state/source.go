package state

import (
	"context"
)

type Source interface {
	Update(ctx context.Context, state State) error
	Get(ctx context.Context) (State, error)
	Exists(ctx context.Context) (bool, error)
}
