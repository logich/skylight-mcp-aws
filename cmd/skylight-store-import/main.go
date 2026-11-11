// Command skylight-store-import moves the Skylight grant saved by
// skylight-login into the DynamoDB grant table, then deletes the local file:
// the refresh token rotates, so exactly one place may hold it.
//
// It looks up the frame id with the saved access token (refreshing it, and
// saving the result first, if it has expired). Uses the admin profile (an
// admin one-off; the Lambda role cannot write new items).
//
//	go run ./cmd/skylight-store-import [-overwrite] [-keep-local]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/logich/skylight-mcp-aws/internal/grant"
	"github.com/logich/skylight-mcp-aws/internal/skylight"
)

func main() {
	def, _ := skylight.DefaultTokenPath()
	path := flag.String("token", def, "local grant file from skylight-login")
	table := flag.String("table", "SkylightMcpGrant", "DynamoDB table")
	profile := flag.String("profile", "skylight-mcp", "AWS profile (admin)")
	overwrite := flag.Bool("overwrite", false, "replace a grant already in the table")
	keep := flag.Bool("keep-local", false, "do not delete the local file afterwards (two holders: avoid)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	saved, err := skylight.LoadFile(*path)
	must(err)
	if saved.AccessToken == "" || (!saved.AccessExpiresAt.IsZero() && time.Now().After(saved.AccessExpiresAt.Add(-5*time.Minute))) {
		r, err := skylight.TokenClient{}.Refresh(ctx, saved.RefreshToken, saved.DeviceFingerprint)
		must(err)
		saved.Apply(r, time.Now())
		must(skylight.SaveFile(*path, saved)) // before the new access token is used
	}
	frameID, err := onlyFrame(ctx, saved.AccessToken)
	must(err)

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithSharedConfigProfile(*profile), awsconfig.WithRegion("us-east-2"))
	must(err)
	st := grant.DynamoStore{API: dynamodb.NewFromConfig(cfg), Table: *table}
	must(st.Seed(ctx, grant.Grant{
		RefreshToken: saved.RefreshToken, AccessToken: saved.AccessToken, AccessExpiresAt: saved.AccessExpiresAt,
		DeviceFingerprint: saved.DeviceFingerprint, FrameID: frameID,
	}, *overwrite, time.Now()))
	got, err := st.Load(ctx)
	must(err)
	if got.RefreshToken != saved.RefreshToken || got.FrameID != frameID {
		must(errors.New("read-back does not match what was written; local file kept"))
	}
	fmt.Printf("stored the grant in %s (generation %d)\n", *table, got.Generation)
	if *keep {
		fmt.Println("WARNING: local file kept; do not use it while the server holds the grant")
		return
	}
	must(os.Remove(*path))
	fmt.Println("deleted the local copy; the table is now the only holder")
}

func onlyFrame(ctx context.Context, accessToken string) (string, error) {
	r, err := skylight.APIClient{}.Get(ctx, accessToken, "/api/frames", nil, skylight.GetOptions{})
	if err != nil {
		return "", err
	}
	if r.Status != 200 {
		return "", fmt.Errorf("frames: HTTP %d", r.Status)
	}
	var doc struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(r.Body, &doc); err != nil {
		return "", errors.New("frames: unexpected response")
	}
	if len(doc.Data) != 1 || doc.Data[0].ID == "" {
		return "", fmt.Errorf("expected exactly one frame, found %d", len(doc.Data))
	}
	return doc.Data[0].ID, nil
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "skylight-store-import:", err)
		os.Exit(1)
	}
}
