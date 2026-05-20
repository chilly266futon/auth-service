package redis

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

type TokenStorage struct {
	client *redis.Client
}

func NewTokenStorageFromClient(client *redis.Client) *TokenStorage {
	return &TokenStorage{client: client}
}

func (s *TokenStorage) StoreRefreshToken(ctx context.Context, userID, token string, ttl time.Duration) error {
	return s.client.Set(ctx, "refresh:"+userID+":"+token, "1", ttl).Err()
}

func (s *TokenStorage) ValidateRefreshToken(ctx context.Context, userID, token string) error {
	key := "refresh:" + userID + ":" + token
	_, err := s.client.Get(ctx, key).Result()
	return err
}

func (s *TokenStorage) RevokeRefreshToken(ctx context.Context, userID, token string) error {
	key := "refresh:" + userID + ":" + token
	return s.client.Del(ctx, key).Err()
}

func (s *TokenStorage) ReplaceRefreshToken(ctx context.Context, userID, oldToken, newToken string, ttl time.Duration) error {
	oldKey := "refresh:" + userID + ":" + oldToken
	newKey := "refresh:" + userID + ":" + newToken

	script := redis.NewScript(`
		if redis.call("EXISTS", KEYS[1]) == 1 then
			redis.call("DEL", KEYS[1])
			redis.call("SET", KEYS[2], "1", "EX", ARGV[1])
			return 1
		else
			return 0
		end
	`)
	keys := []string{oldKey, newKey}
	args := []interface{}{int(ttl.Seconds())}
	result, err := script.Run(ctx, s.client, keys, args...).Result()
	if err != nil {
		return err
	}
	if result.(int64) == 0 {
		return errors.New("old token not found")
	}
	return nil
}

func (s *TokenStorage) RefreshToken(ctx context.Context, userID, token string, ttl time.Duration) error {
	oldKey := "refresh:" + userID + ":" + token

	exists, err := s.client.Exists(ctx, oldKey).Result()
	if err != nil {
		return err
	}
	if exists == 0 {
		return errors.New("old token not found")
	}

	pipe := s.client.Pipeline()
	pipe.Del(ctx, oldKey)
	pipe.Set(ctx, "refresh:"+userID+":"+token, "1", ttl)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *TokenStorage) Ping(ctx context.Context) (string, error) {
	return s.client.Ping(ctx).Result()
}

func (s *TokenStorage) Close(ctx context.Context) error {
	return s.client.Close()
}
