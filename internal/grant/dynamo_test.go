package grant

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/logich/skylight-mcp-aws/internal/skylight"
)

// fakeDynamo evaluates exactly the expressions DynamoStore sends, so the
// conditional-write logic is exercised end to end. Unknown expressions fail
// the test, which keeps the fake honest when the store changes.
type fakeDynamo struct {
	t    *testing.T
	mu   sync.Mutex
	item map[string]types.AttributeValue
}

var errCond = &types.ConditionalCheckFailedException{Message: aws.String("failed")}

func (f *fakeDynamo) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if in.ConsistentRead == nil || !*in.ConsistentRead {
		f.t.Error("GetItem without ConsistentRead")
	}
	cp := map[string]types.AttributeValue{}
	for k, v := range f.item {
		cp[k] = v
	}
	return &dynamodb.GetItemOutput{Item: cp}, nil
}

func (f *fakeDynamo) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if in.ConditionExpression != nil {
		if *in.ConditionExpression != "attribute_not_exists(pk)" {
			f.t.Fatalf("unexpected put condition %q", *in.ConditionExpression)
		}
		if len(f.item) > 0 {
			return nil, errCond
		}
	}
	f.item = in.Item
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDynamo) str(k string) (string, bool) {
	v, ok := f.item[k].(*types.AttributeValueMemberS)
	if !ok {
		return "", false
	}
	return v.Value, true
}

func (f *fakeDynamo) num(k string) (int64, bool) {
	v, ok := f.item[k].(*types.AttributeValueMemberN)
	if !ok {
		return 0, false
	}
	i, _ := strconv.ParseInt(v.Value, 10, 64)
	return i, true
}

func val(vals map[string]types.AttributeValue, k string) string {
	switch v := vals[k].(type) {
	case *types.AttributeValueMemberS:
		return v.Value
	case *types.AttributeValueMemberN:
		return v.Value
	}
	return ""
}

func (f *fakeDynamo) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cond, upd, v := *in.ConditionExpression, *in.UpdateExpression, in.ExpressionAttributeValues
	owner, hasOwner := f.str("lease_owner")
	switch cond {
	case "attribute_exists(pk) AND (attribute_not_exists(lease_expires_at) OR lease_expires_at < :now OR lease_owner = :o)":
		exp, hasExp := f.num("lease_expires_at")
		now, _ := strconv.ParseInt(val(v, ":now"), 10, 64)
		if len(f.item) == 0 || !(!hasExp || exp < now || (hasOwner && owner == val(v, ":o"))) {
			return nil, errCond
		}
	case "lease_owner = :o AND generation = :g":
		gen, _ := f.num("generation")
		if !hasOwner || owner != val(v, ":o") || strconv.FormatInt(gen, 10) != val(v, ":g") {
			return nil, errCond
		}
	case "lease_owner = :o":
		if !hasOwner || owner != val(v, ":o") {
			return nil, errCond
		}
	default:
		f.t.Fatalf("unexpected condition %q", cond)
	}
	setPart, removePart, _ := strings.Cut(upd, " REMOVE ")
	if strings.HasPrefix(upd, "REMOVE ") {
		setPart, removePart = "", strings.TrimPrefix(upd, "REMOVE ")
	}
	for a := range strings.SplitSeq(strings.TrimPrefix(setPart, "SET "), ", ") {
		if a == "" {
			continue
		}
		name, expr, _ := strings.Cut(a, " = ")
		if name == "generation" && expr == "generation + :one" {
			g, _ := f.num("generation")
			f.item["generation"] = n(g + 1)
			continue
		}
		f.item[name] = v[expr]
	}
	for _, name := range strings.Split(removePart, ", ") {
		delete(f.item, strings.TrimSpace(name))
	}
	return &dynamodb.UpdateItemOutput{}, nil
}

func TestDynamoStoreWithManager(t *testing.T) {
	ctx := context.Background()
	fd := &fakeDynamo{t: t}
	st := DynamoStore{API: fd, Table: "SkylightMcpTokens"}
	if _, err := st.Load(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty load: %v", err)
	}
	seed := Grant{RefreshToken: "rt0", AccessToken: "at0", AccessExpiresAt: t0.Add(-time.Hour), DeviceFingerprint: "fp", FrameID: "f1"}
	if err := st.Seed(ctx, seed, false, t0); err != nil {
		t.Fatal(err)
	}
	if err := st.Seed(ctx, seed, false, t0); err == nil {
		t.Fatal("seed overwrote without permission")
	}
	g, err := st.Load(ctx)
	if err != nil || g.RefreshToken != "rt0" || g.FrameID != "f1" || g.Generation != 0 || !g.AccessExpiresAt.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("load %+v %v", g, err)
	}

	// Lease semantics.
	if ok, _ := st.AcquireLease(ctx, "a", t0, 10*time.Second); !ok {
		t.Fatal("free lease not acquired")
	}
	if ok, _ := st.AcquireLease(ctx, "b", t0.Add(time.Second), 10*time.Second); ok {
		t.Fatal("held lease acquired by another owner")
	}
	if ok, _ := st.AcquireLease(ctx, "b", t0.Add(11*time.Second), 10*time.Second); !ok {
		t.Fatal("expired lease not taken over")
	}
	if err := st.Commit(ctx, "a", 0, "x", "y", t0, t0); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("commit by former owner: %v", err)
	}
	if err := st.Commit(ctx, "b", 5, "x", "y", t0, t0); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("commit with stale generation: %v", err)
	}
	if err := st.Release(ctx, "a"); err != nil {
		t.Fatalf("release by non-owner should be a no-op: %v", err)
	}
	if err := st.Release(ctx, "b"); err != nil {
		t.Fatal(err)
	}

	// Full refresh through the Manager, then a non-rotating response.
	dk := newDoorkeeper("rt0")
	tok, err := mgr(st, dk, t0).AccessToken(ctx, "")
	if err != nil || tok.AccessToken != "at1" {
		t.Fatalf("%+v %v", tok, err)
	}
	g, _ = st.Load(ctx)
	if g.RefreshToken != "rt1" || g.Generation != 1 || g.LeaseOwner != "" || !g.LeaseExpiresAt.IsZero() {
		t.Fatalf("after refresh %+v", g)
	}
	nr := refresherFunc(func(context.Context, string, string) (skylight.TokenResponse, error) {
		return skylight.TokenResponse{AccessToken: "at-nr", ExpiresIn: 60}, nil
	})
	if _, err := mgr(st, nr, t0).AccessToken(ctx, "at1"); err != nil {
		t.Fatal(err)
	}
	g, _ = st.Load(ctx)
	if g.RefreshToken != "rt1" || g.AccessToken != "at-nr" || g.Generation != 2 {
		t.Fatalf("non-rotating refresh %+v", g)
	}
}

func TestDynamoErrorsDoNotEchoValues(t *testing.T) {
	st := DynamoStore{API: errDynamo{}, Table: "T"}
	_, err := st.Load(context.Background())
	if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("err %v", err)
	}
}

type errDynamo struct{}

type apiErr struct{}

func (apiErr) Error() string     { return "AccessDenied: value SECRET-TOKEN not allowed" }
func (apiErr) ErrorCode() string { return "AccessDenied" }

func (errDynamo) GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	return nil, apiErr{}
}
func (errDynamo) PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	return nil, apiErr{}
}
func (errDynamo) UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	return nil, apiErr{}
}
