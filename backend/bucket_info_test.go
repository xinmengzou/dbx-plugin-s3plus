package main

import (
	"errors"
	"testing"

	"github.com/minio/minio-go/v7"
)

func TestClassifyBucketCapability(test *testing.T) {
	for _, code := range []string{
		"NoSuchBucketPolicy",
		"NoSuchBucketEncryption",
		"NoSuchLifecycleConfiguration",
		"NoSuchCORSConfiguration",
	} {
		got := classifyBucketCapability(minio.ErrorResponse{Code: code, StatusCode: 404})
		if got.Status != bucketCapUnconfigured {
			test.Fatalf("%s classified as %q, want unconfigured", code, got.Status)
		}
		if got.Detail != "" {
			test.Fatalf("unconfigured should carry no detail, got %q", got.Detail)
		}
	}

	for _, tc := range []struct {
		err      minio.ErrorResponse
		expected string
	}{
		{minio.ErrorResponse{Code: "NotImplemented", StatusCode: 501}, bucketCapUnsupported},
		{minio.ErrorResponse{Code: "NotSupported", StatusCode: 400}, bucketCapUnsupported},
		{minio.ErrorResponse{Code: "MethodNotAllowed", StatusCode: 405}, bucketCapUnsupported},
		{minio.ErrorResponse{Code: "AccessDenied", StatusCode: 403}, bucketCapError},
		{minio.ErrorResponse{Code: "NoSuchBucket", StatusCode: 404}, bucketCapError},
	} {
		got := classifyBucketCapability(tc.err)
		if got.Status != tc.expected {
			test.Fatalf("%s classified as %q, want %q", tc.err.Code, got.Status, tc.expected)
		}
	}

	got := classifyBucketCapability(errors.New("connection reset"))
	if got.Status != bucketCapError || got.Detail == "" {
		test.Fatalf("non-S3 error classified %#v", got)
	}
}

func TestSummarizeBucketPolicy(test *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::b/*"]},` +
		`{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::b/*"]},` +
		`{"Effect":"Deny","Action":["s3:DeleteObject"],"Resource":["arn:aws:s3:::b/*"]}]}`
	if got := summarizeBucketPolicy(policy); got != "3 statements (2 allow / 1 deny)" {
		test.Fatalf("summary mismatch: %q", got)
	}
	if got := summarizeBucketPolicy("not-json"); got == "" {
		test.Fatal("invalid policy should fall back to a byte-count summary")
	}
}
