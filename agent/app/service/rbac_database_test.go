package service

import (
	"reflect"
	"testing"
)

func TestDatabaseResourceKey(t *testing.T) {
	got := DatabaseResourceKey("MySQL", "local-mysql", "app_db")
	if got != "mysql:local-mysql:app_db" {
		t.Fatalf("unexpected key %q", got)
	}
}

func TestAllowedDatabaseNames(t *testing.T) {
	keys := []string{
		"mysql:local:one",
		"postgresql:local:two",
		"mysql:local:three",
		"mysql:other:four",
		"mysql:local:one",
	}
	got := AllowedDatabaseNames(keys, "mysql", "local")
	want := []string{"one", "three"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
