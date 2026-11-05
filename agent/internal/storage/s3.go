// Package storage is the S3-compatible client: streaming multipart uploads,
// the backup object layout and retention (design doc §3.3).
package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/desnarong/pgsafe/agent/internal/config"
)

const (
	// 64 MiB parts x 10,000 parts = 640 GiB max object; with 2 concurrent
	// parts, upload buffering stays around 128 MiB regardless of DB size.
	partSize    = 64 << 20
	concurrency = 2
)

// ErrNotFound is returned when an object does not exist.
var ErrNotFound = errors.New("object not found")

// Store is an S3-compatible bucket under a key prefix. All keys passed to its
// methods are relative to the prefix.
type Store struct {
	client *s3.Client
	bucket string
	prefix string
}

// New builds a client using the standard AWS credential chain (env vars,
// shared config, IAM role). Credentials are never part of pgsafe.yaml.
func New(ctx context.Context, sc config.Storage) (*Store, error) {
	region := sc.Region
	if region == "" {
		region = "us-east-1"
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		// The SDK's default CRC checksums are rejected by several S3-compatible
		// services (R2, B2, older MinIO); only send them when required.
		awsconfig.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
		awsconfig.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if sc.Endpoint != "" {
			o.BaseEndpoint = aws.String(sc.Endpoint)
			o.UsePathStyle = true
		}
	})
	return &Store{client: client, bucket: sc.Bucket, prefix: sc.NormPrefix()}, nil
}

func (s *Store) key(rel string) string { return s.prefix + strings.TrimLeft(rel, "/") }

// Describe returns "s3://bucket/prefix" for messages.
func (s *Store) Describe() string { return "s3://" + s.bucket + "/" + s.prefix }

// Upload streams r to key with multipart upload; the size need not be known.
// If r returns an error the multipart upload is aborted.
func (s *Store) Upload(ctx context.Context, key string, r io.Reader) error {
	up := manager.NewUploader(s.client, func(u *manager.Uploader) {
		u.PartSize = partSize
		u.Concurrency = concurrency
		u.LeavePartsOnError = false
	})
	_, err := up.Upload(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(s.key(key)),
		Body:        r,
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		return fmt.Errorf("upload %s: %w", key, err)
	}
	return nil
}

// PutBytes writes a small object.
func (s *Store) PutBytes(ctx context.Context, key string, data []byte, contentType string) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(s.key(key)),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	return nil
}

// Get opens an object for streaming. The caller closes it.
func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(s.key(key))})
	if err != nil {
		if isNotFound(err) {
			return nil, 0, fmt.Errorf("%s: %w", key, ErrNotFound)
		}
		return nil, 0, fmt.Errorf("get %s: %w", key, err)
	}
	return out.Body, aws.ToInt64(out.ContentLength), nil
}

// GetBytes reads a small object fully.
func (s *Store) GetBytes(ctx context.Context, key string) ([]byte, error) {
	rc, _, err := s.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 64<<20))
}

// List returns keys (relative to the store prefix) under prefix.
func (s *Store) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(s.key(prefix)),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", prefix, err)
		}
		for _, o := range page.Contents {
			keys = append(keys, strings.TrimPrefix(aws.ToString(o.Key), s.prefix))
		}
	}
	return keys, nil
}

// Delete removes keys (in batches of 1000).
func (s *Store) Delete(ctx context.Context, keys ...string) error {
	for len(keys) > 0 {
		n := min(len(keys), 1000)
		objs := make([]types.ObjectIdentifier, n)
		for i, k := range keys[:n] {
			objs[i] = types.ObjectIdentifier{Key: aws.String(s.key(k))}
		}
		out, err := s.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(s.bucket),
			Delete: &types.Delete{Objects: objs, Quiet: aws.Bool(true)},
		})
		if err != nil {
			return fmt.Errorf("delete objects: %w", err)
		}
		if len(out.Errors) > 0 {
			return fmt.Errorf("delete %s: %s", aws.ToString(out.Errors[0].Key), aws.ToString(out.Errors[0].Message))
		}
		keys = keys[n:]
	}
	return nil
}

func isNotFound(err error) bool {
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var api smithy.APIError
	return errors.As(err, &api) && (api.ErrorCode() == "NotFound" || api.ErrorCode() == "NoSuchKey")
}
