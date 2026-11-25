package repository

import (
	"context"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"gorm.io/gorm"
)

// NotificationRepository persists notification configurations.
type NotificationRepository interface {
	Migrate(ctx context.Context) error
	Create(ctx context.Context, item *entity.Notification) error
	FindByID(ctx context.Context, id int64) (*entity.Notification, error)
	List(ctx context.Context, page, pageSize int) (*dto.PageResult[entity.Notification], error)
	FindEnabled(ctx context.Context, event string, afterID int64, limit int) ([]entity.Notification, error)
	Update(ctx context.Context, item *entity.Notification, replaceWebhook bool) error
	Delete(ctx context.Context, id int64) (int64, error)
}

type notificationRepository struct{ db *gorm.DB }

// NewNotificationRepository creates notification storage.
func NewNotificationRepository(db *gorm.DB) NotificationRepository {
	return &notificationRepository{db: db}
}

// Create inserts a configuration with a plaintext webhook.
func (r *notificationRepository) Create(ctx context.Context, item *entity.Notification) error {
	return r.db.WithContext(ctx).Create(item).Error
}

// FindByID returns one configuration.
func (r *notificationRepository) FindByID(ctx context.Context, id int64) (*entity.Notification, error) {
	var item entity.Notification
	if err := r.db.WithContext(ctx).First(&item, id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

// List returns bounded pages ordered by descending ID.
func (r *notificationRepository) List(ctx context.Context, page, pageSize int) (*dto.PageResult[entity.Notification], error) {
	query := r.db.WithContext(ctx).Model(&entity.Notification{})
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}
	items := make([]entity.Notification, 0)
	if err := query.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&items).Error; err != nil {
		return nil, err
	}
	return &dto.PageResult[entity.Notification]{Page: page, PageSize: pageSize, Total: int(total), TotalPages: int((total + int64(pageSize) - 1) / int64(pageSize)), Items: items}, nil
}

// FindEnabled uses keyset pagination for matching event subscriptions.
func (r *notificationRepository) FindEnabled(ctx context.Context, event string, afterID int64, limit int) ([]entity.Notification, error) {
	items := make([]entity.Notification, 0)
	err := r.db.WithContext(ctx).Where("event = ? AND enabled = ? AND id > ?", event, true, afterID).Order("id ASC").Limit(limit).Find(&items).Error
	return items, err
}

// Update also persists false switches and preserves an omitted webhook.
func (r *notificationRepository) Update(ctx context.Context, item *entity.Notification, replaceWebhook bool) error {
	values := map[string]any{"name": item.Name, "description": item.Description, "enabled": item.Enabled, "event": item.Event, "style": item.Style}
	if replaceWebhook {
		values["webhook"] = item.Webhook
	}
	return r.db.WithContext(ctx).Model(&entity.Notification{}).Where("id = ?", item.ID).Updates(values).Error
}

// Delete removes a configuration and reports the affected row count.
func (r *notificationRepository) Delete(ctx context.Context, id int64) (int64, error) {
	result := r.db.WithContext(ctx).Delete(&entity.Notification{}, id)
	return result.RowsAffected, result.Error
}

// Migrate initializes only the notification table and ensures Chinese names are supported.
func (r *notificationRepository) Migrate(ctx context.Context) error {
	db := r.db.WithContext(ctx)
	if db.Dialector.Name() == "mysql" {
		db = db.Set("gorm:table_options", "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
	}
	if err := db.AutoMigrate(&entity.Notification{}); err != nil {
		return err
	}
	if db.Dialector.Name() != "mysql" {
		return nil
	}
	var columns int64
	if err := db.Raw("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND character_set_name IS NOT NULL AND character_set_name <> ?", "manscan_notifications", "utf8mb4").Scan(&columns).Error; err != nil {
		return err
	}
	if columns > 0 {
		return db.Exec("ALTER TABLE manscan_notifications CONVERT TO CHARACTER SET utf8mb4").Error
	}
	return nil
}
