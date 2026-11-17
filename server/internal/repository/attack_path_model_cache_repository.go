package repository

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"

	"ManScan/server/internal/model/entity"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// AttackPathModelCacheRepository persists validated keep/drop decisions.
type AttackPathModelCacheRepository interface {
	FindByKeys(ctx context.Context, keys []string) (map[string]bool, error)
	Save(ctx context.Context, decisions map[string]bool) error
	Close() error
}

type attackPathModelCacheRepository struct{ db *gorm.DB }

// NewAttackPathModelCacheRepository opens a private, indexed cache file.
func NewAttackPathModelCacheRepository(ctx context.Context, path string) (AttackPathModelCacheRepository, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	directory := filepath.Dir(abs)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("cache directory must be a real directory")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(abs); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("cache file must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	permissionErr := file.Chmod(0600)
	if err := errors.Join(permissionErr, file.Close()); err != nil {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: abs}).String() + "?_busy_timeout=5000&_journal_mode=WAL&_synchronous=FULL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, err
	}
	r := &attackPathModelCacheRepository{db: db}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	// Serialize short disk operations only; model calls never hold this connection.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	if err := db.WithContext(ctx).AutoMigrate(&entity.AttackPathModelCache{}); err != nil {
		return nil, errors.Join(err, r.Close())
	}
	return r, nil
}

// FindByKeys distinguishes an absent record from a cached normal decision.
func (r *attackPathModelCacheRepository) FindByKeys(ctx context.Context, keys []string) (map[string]bool, error) {
	result := make(map[string]bool, len(keys))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for start := 0; start < len(keys); start += 400 {
		var rows []entity.AttackPathModelCache
		if err := r.db.WithContext(ctx).Where("key IN ?", keys[start:min(start+400, len(keys))]).Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, row := range rows {
			result[row.Key] = row.Malicious
		}
	}
	return result, nil
}

// Save atomically commits a validated batch, preserving the first stored decision.
func (r *attackPathModelCacheRepository) Save(ctx context.Context, decisions map[string]bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(decisions) == 0 {
		return nil
	}
	rows := make([]entity.AttackPathModelCache, 0, len(decisions))
	for key, malicious := range decisions {
		rows = append(rows, entity.AttackPathModelCache{Key: key, Malicious: malicious})
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(rows, 200).Error
	})
}

// Close flushes and releases the local cache database.
func (r *attackPathModelCacheRepository) Close() error {
	db, err := r.db.DB()
	if err != nil {
		return err
	}
	return db.Close()
}
