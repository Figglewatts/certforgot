package state

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path"

	"gopkg.in/yaml.v3"
)

type LocalSource struct {
	directory string
}

const (
	FileName = "certforgot_state.yaml"
)

func NewLocalSource(directory string) (LocalSource, error) {
	if err := os.MkdirAll(directory, 0755); err != nil {
		return LocalSource{}, err
	}
	return LocalSource{directory}, nil
}

func (source LocalSource) Update(ctx context.Context, state State) error {
	marshaledState, err := yaml.Marshal(&state)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(source.statePath(), marshaledState, 0644)
}

func (source LocalSource) Get(ctx context.Context) (State, error) {
	s := State{}

	marshaledState, err := ioutil.ReadFile(source.statePath())
	if err != nil {
		return s, err
	}

	if err := yaml.Unmarshal(marshaledState, &s); err != nil {
		return s, err
	}

	return s, nil
}

func (source LocalSource) Exists(ctx context.Context) (bool, error) {
	_, err := os.Stat(source.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	} else {
		return true, nil
	}
}

func (source LocalSource) statePath() string {
	return path.Join(source.directory, FileName)
}
