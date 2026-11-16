package repository

import (
	"context"
	"time"

	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
)

type AttackPathTaskRepository interface {
	Create(ctx context.Context, task *entity.AttackPathTask) error
	FindOwned(ctx context.Context, id string, ownerID int64) (*entity.AttackPathTask, error)
	FindOutputOwned(ctx context.Context, id string, ownerID int64) (*entity.AttackPathTask, error)
	ClaimNext(ctx context.Context, token string, now time.Time) (*entity.AttackPathTask, error)
	Renew(ctx context.Context, id, token string, until time.Time) error
	UpdateProgress(ctx context.Context, id, token string, processed, kept int) error
	Finish(ctx context.Context, id, token, status, output, message string, processed, kept int) error
	Cancel(ctx context.Context, id string, ownerID int64) (bool, error)
}

type attackPathTaskRepository struct{ db *gorm.DB }

// NewAttackPathTaskRepository creates the persistent queue implementation.
func NewAttackPathTaskRepository(db *gorm.DB) AttackPathTaskRepository {
	return &attackPathTaskRepository{db: db}
}

func (r *attackPathTaskRepository) Create(ctx context.Context, task *entity.AttackPathTask) error {
	return r.db.WithContext(ctx).Create(task).Error
}

func (r *attackPathTaskRepository) FindOwned(ctx context.Context, id string, ownerID int64) (*entity.AttackPathTask, error) {
	var task entity.AttackPathTask
	err := r.db.WithContext(ctx).Select("id", "owner_user_id", "status", "total", "processed", "kept", "error_message", "created_at", "finished_at").Where("id = ? AND owner_user_id = ?", id, ownerID).First(&task).Error
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (r *attackPathTaskRepository) FindOutputOwned(ctx context.Context, id string, ownerID int64) (*entity.AttackPathTask, error) {
	var task entity.AttackPathTask
	err := r.db.WithContext(ctx).Select("status", "output_file_name").Where("id = ? AND owner_user_id = ?", id, ownerID).First(&task).Error
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (r *attackPathTaskRepository) ClaimNext(ctx context.Context, token string, now time.Time) (*entity.AttackPathTask, error) {
	for attempt := 0; attempt < 4; attempt++ {
		var task entity.AttackPathTask
		err := r.db.WithContext(ctx).Select("id", "owner_user_id", "status", "total").Where("status = ? OR (status = ? AND lease_until < ?)", "queued", "running", now).Order("created_at ASC").First(&task).Error
		if err != nil {
			return nil, err
		}
		result := r.db.WithContext(ctx).Model(&entity.AttackPathTask{}).
			Where("id = ? AND (status = ? OR (status = ? AND lease_until < ?))", task.ID, "queued", "running", now).
			Updates(map[string]interface{}{"status": "running", "lease_token": token, "lease_until": now.Add(45 * time.Second), "processed": 0, "kept": 0})
		if result.Error != nil {
			return nil, result.Error
		}
		if result.RowsAffected == 1 {
			task.Status = "running"
			task.LeaseToken = token
			return &task, nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}

func (r *attackPathTaskRepository) Renew(ctx context.Context, id, token string, until time.Time) error {
	result := r.db.WithContext(ctx).Model(&entity.AttackPathTask{}).Where("id = ? AND lease_token = ? AND status = ?", id, token, "running").Update("lease_until", until)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *attackPathTaskRepository) UpdateProgress(ctx context.Context, id, token string, processed, kept int) error {
	result := r.db.WithContext(ctx).Model(&entity.AttackPathTask{}).Where("id = ? AND lease_token = ? AND status = ?", id, token, "running").Updates(map[string]interface{}{"processed": processed, "kept": kept})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *attackPathTaskRepository) Finish(ctx context.Context, id, token, status, output, message string, processed, kept int) error {
	now := time.Now()
	result := r.db.WithContext(ctx).Model(&entity.AttackPathTask{}).Where("id = ? AND lease_token = ? AND status = ?", id, token, "running").Updates(map[string]interface{}{
		"status": status, "output_file_name": output, "error_message": message, "processed": processed, "kept": kept, "finished_at": now, "lease_token": "", "lease_until": nil,
	})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *attackPathTaskRepository) Cancel(ctx context.Context, id string, ownerID int64) (bool, error) {
	now := time.Now()
	result := r.db.WithContext(ctx).Model(&entity.AttackPathTask{}).Where("id = ? AND owner_user_id = ? AND status IN ?", id, ownerID, []string{"queued", "running"}).Updates(map[string]interface{}{"status": "cancelled", "finished_at": now, "lease_token": "", "lease_until": nil})
	return result.RowsAffected == 1, result.Error
}
