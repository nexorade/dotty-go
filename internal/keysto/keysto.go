package keysto

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

type InitOptions = redis.Options

const Nil = redis.Nil

type Client struct {
	redis *redis.Client
}

var client Client = Client{}

func Initialise(opts *InitOptions) {
	if client.redis != nil {
		panic("Keysto is already initialised. Make sure you initialise the module only once.")
	}

	if opts == nil {
		defaultAddr := os.Getenv("REDIS_HOST") + ":" + os.Getenv("REDIS_PORT")
		defaultPassword := os.Getenv("REDIS_PASSWORD")
		opts = &InitOptions{
			Addr:     defaultAddr,
			Password: defaultPassword,
			DB:       0,
		}
	}

	rdb := redis.NewClient(opts)
	client.redis = rdb
}

func GetClient() *Client {
	if client.redis == nil {
		panic("Please initialise Keysto before trying GetClient")
	}

	return &client
}

func (c *Client) Set(ctx context.Context, key string, value interface{}, expiry_duration time.Duration) error {
	v, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.redis.Set(ctx, key, v, expiry_duration).Err()

}

func (c *Client) Get(ctx context.Context, key string, destination interface{}) error {
	v, err := c.redis.Get(ctx, key).Result()

	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(v), destination)
}

func (c *Client) Delete(ctx context.Context, key string) error {
	return c.redis.Del(ctx, key).Err()
}

func (c *Client) Update(ctx context.Context, key string, value interface{}, expiry_duration time.Duration) error {
	v, err := json.Marshal(value)

	if err != nil {
		return err
	}

	delErr := c.redis.Del(ctx, key).Err()

	if delErr != nil {
		return delErr
	}
	return c.redis.Set(ctx, key, v, expiry_duration).Err()
}

func Clean() {
	if client.redis == nil {
		panic("Keysto was not initialised. Clean up is not possible")
	}

	err := client.redis.Close()

	if err != nil {
		panic("Unable to clean up Keysto")
	}
}
