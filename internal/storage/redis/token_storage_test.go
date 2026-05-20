package redis

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func TestTokenStorage_ExpiredToken(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6380",
		DB:   15, // тестовая база
	})
	defer client.FlushDB(context.Background())

	ts := NewTokenStorageFromClient(client)
	ctx := context.Background()
	userID := "user1"
	token := "tok123"

	// Сохраняем refresh token с коротким TTL
	err := ts.StoreRefreshToken(ctx, userID, token, 1*time.Second)
	assert.NoError(t, err)

	// Сразу должен быть валиден
	err = ts.ValidateRefreshToken(ctx, userID, token)
	assert.NoError(t, err)

	// Ждём пока истечёт TTL
	time.Sleep(2 * time.Second)

	// Теперь должен быть невалиден (redis: nil)
	err = ts.ValidateRefreshToken(ctx, userID, token)
	assert.Error(t, err)
	assert.Equal(t, redis.Nil, err)
}

func TestTokenStorage_ReplaceRefreshToken(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6380",
		DB:   15,
	})
	defer client.FlushDB(context.Background())

	ts := NewTokenStorageFromClient(client)
	ctx := context.Background()
	userID := "user1"
	oldToken := "old123"
	newToken := "new456"
	ttl := 10 * time.Second

	// 1. Старого токена нет -> ошибка
	err := ts.ReplaceRefreshToken(ctx, userID, oldToken, newToken, ttl)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "old token not found")

	// 2. Сохраняем старый токен
	err = ts.StoreRefreshToken(ctx, userID, oldToken, ttl)
	assert.NoError(t, err)

	// Проверяем, что старый токен валиден
	err = ts.ValidateRefreshToken(ctx, userID, oldToken)
	assert.NoError(t, err)

	// 3. Заменяем старый на новый
	err = ts.ReplaceRefreshToken(ctx, userID, oldToken, newToken, ttl)
	assert.NoError(t, err)

	// Старый токен должен стать невалидным
	err = ts.ValidateRefreshToken(ctx, userID, oldToken)
	assert.Error(t, err)
	assert.Equal(t, redis.Nil, err)

	// Новый токен должен быть валиден
	err = ts.ValidateRefreshToken(ctx, userID, newToken)
	assert.NoError(t, err)

	// 4. Попытка повторной замены с тем же старым токеном должна провалиться (старый уже удалён)
	err = ts.ReplaceRefreshToken(ctx, userID, oldToken, "another", ttl)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "old token not found")
}
