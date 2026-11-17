package repository

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAttackPathModelCacheRepositoryPersistence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", "decisions.sqlite")
	r, err := NewAttackPathModelCacheRepository(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	decisions := make(map[string]bool, 1000)
	keys := make([]string, 0, 1001)
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("%064x", i)
		keys = append(keys, key)
		decisions[key] = i%2 == 0
	}
	if err := r.Save(ctx, decisions); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(ctx, map[string]bool{keys[0]: false}); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = NewAttackPathModelCacheRepository(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	got, err := r.FindByKeys(ctx, append(keys, "missing"))
	if err != nil || !reflect.DeepEqual(got, decisions) {
		t.Fatalf("reopened decisions differ: count=%d err=%v", len(got), err)
	}
	for name, want := range map[string]os.FileMode{path: 0600, filepath.Dir(path): 0700} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("permissions=%o want=%o", info.Mode().Perm(), want)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := r.Save(cancelled, map[string]bool{"cancelled": true}); err == nil {
		t.Fatal("cancelled write succeeded")
	}
	got, err = r.FindByKeys(ctx, []string{"cancelled"})
	if err != nil || len(got) != 0 {
		t.Fatalf("cancelled result was cached: %v %v", got, err)
	}
	if _, err := r.FindByKeys(cancelled, keys); err == nil {
		t.Fatal("cancelled read succeeded")
	}
}

func TestAttackPathModelCacheRepositoryRejectsInvalidStorage(t *testing.T) {
	for _, kind := range []string{"corrupt", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cache.sqlite")
			var err error
			switch kind {
			case "corrupt":
				err = os.WriteFile(path, []byte("not a sqlite database"), 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink":
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, nil, 0600); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(target, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			r, err := NewAttackPathModelCacheRepository(context.Background(), path)
			if err == nil {
				if closeErr := r.Close(); closeErr != nil {
					t.Error(closeErr)
				}
				t.Fatal("invalid storage accepted")
			}
		})
	}
}
