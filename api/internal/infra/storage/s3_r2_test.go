package storage

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestNewS3Storage_ChecksumOptionsOnlyForCustomEndpoints(t *testing.T) {
	custom := newS3Storage("b", "auto", "https://abc.r2.cloudflarestorage.com", "a", "s", nil)
	o := custom.client.Options()
	if o.RequestChecksumCalculation != aws.RequestChecksumCalculationWhenRequired ||
		o.ResponseChecksumValidation != aws.ResponseChecksumValidationWhenRequired {
		t.Fatalf("custom endpoint: calc=%v validate=%v", o.RequestChecksumCalculation, o.ResponseChecksumValidation)
	}
	awsS3 := newS3Storage("b", "eu-west-1", "", "a", "s", nil)
	o = awsS3.client.Options()
	// Unset (zero) keeps the SDK default, which is "when supported".
	if o.RequestChecksumCalculation == aws.RequestChecksumCalculationWhenRequired ||
		o.ResponseChecksumValidation == aws.ResponseChecksumValidationWhenRequired {
		t.Fatalf("AWS: calc=%v validate=%v", o.RequestChecksumCalculation, o.ResponseChecksumValidation)
	}
}

func TestSetServerSideEncryption_R2Refused(t *testing.T) {
	r2 := newS3Storage("b", "auto", "https://abc.eu.r2.cloudflarestorage.com", "a", "s", nil)
	for _, c := range [][2]string{{"AES256", ""}, {"aws:kms", "k"}, {"", "k"}} {
		err := r2.SetServerSideEncryption(c[0], c[1])
		if err == nil || !strings.Contains(err.Error(), "R2 always encrypts at rest") {
			t.Fatalf("%v: err = %v", c, err)
		}
	}
	if err := r2.SetServerSideEncryption("", ""); err != nil {
		t.Fatal(err)
	}
	minio := newS3Storage("b", "", "http://minio:9000", "a", "s", nil)
	if err := minio.SetServerSideEncryption("AES256", ""); err != nil {
		t.Fatal(err)
	}
}
