package grant

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// DynamoAPI is the subset of the DynamoDB client the store uses.
type DynamoAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

// DynamoStore keeps the grant as one item (pk = "grant") in a table encrypted
// with a customer-managed KMS key. Errors never include attribute values.
type DynamoStore struct {
	API   DynamoAPI
	Table string
}

const itemKey = "grant"

func (d DynamoStore) key() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"pk": &types.AttributeValueMemberS{Value: itemKey}}
}

func s(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }
func n(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}

func millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMillis(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func isConditionFailure(err error) bool {
	var c *types.ConditionalCheckFailedException
	return errors.As(err, &c)
}

// opError hides SDK error details that could echo request values; the
// operation name and error code are enough to debug.
func opError(op string, err error) error {
	code := "error"
	var apiErr interface{ ErrorCode() string }
	if errors.As(err, &apiErr) {
		code = apiErr.ErrorCode()
	}
	return fmt.Errorf("grant store %s: %s", op, code)
}

func (d DynamoStore) Load(ctx context.Context) (Grant, error) {
	out, err := d.API.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(d.Table), Key: d.key(), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return Grant{}, opError("load", err)
	}
	if len(out.Item) == 0 {
		return Grant{}, ErrNotFound
	}
	str := func(k string) string {
		if v, ok := out.Item[k].(*types.AttributeValueMemberS); ok {
			return v.Value
		}
		return ""
	}
	num := func(k string) int64 {
		if v, ok := out.Item[k].(*types.AttributeValueMemberN); ok {
			i, _ := strconv.ParseInt(v.Value, 10, 64)
			return i
		}
		return 0
	}
	g := Grant{
		RefreshToken: str("refresh_token"), AccessToken: str("access_token"),
		AccessExpiresAt: fromMillis(num("access_expires_at")), DeviceFingerprint: str("device_fingerprint"),
		FrameID: str("frame_id"), Generation: num("generation"),
		LeaseOwner: str("lease_owner"), LeaseExpiresAt: fromMillis(num("lease_expires_at")),
	}
	if g.RefreshToken == "" || g.DeviceFingerprint == "" || g.FrameID == "" {
		return Grant{}, errors.New("grant store load: item is incomplete; re-run the store import")
	}
	return g, nil
}

func (d DynamoStore) AcquireLease(ctx context.Context, owner string, now time.Time, ttl time.Duration) (bool, error) {
	_, err := d.API.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(d.Table),
		Key:                 d.key(),
		UpdateExpression:    aws.String("SET lease_owner = :o, lease_expires_at = :exp"),
		ConditionExpression: aws.String("attribute_exists(pk) AND (attribute_not_exists(lease_expires_at) OR lease_expires_at < :now OR lease_owner = :o)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":o": s(owner), ":exp": n(now.Add(ttl).UnixMilli()), ":now": n(now.UnixMilli()),
		},
	})
	if isConditionFailure(err) {
		return false, nil
	}
	if err != nil {
		return false, opError("acquire lease", err)
	}
	return true, nil
}

func (d DynamoStore) Commit(ctx context.Context, owner string, gen int64, rt, at string, exp, now time.Time) error {
	set := "SET access_token = :a, access_expires_at = :e, generation = generation + :one, updated_at = :u"
	vals := map[string]types.AttributeValue{
		":a": s(at), ":e": n(millis(exp)), ":one": n(1), ":u": n(now.UnixMilli()),
		":o": s(owner), ":g": n(gen),
	}
	if rt != "" {
		set += ", refresh_token = :r"
		vals[":r"] = s(rt)
	}
	_, err := d.API.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(d.Table),
		Key:                       d.key(),
		UpdateExpression:          aws.String(set + " REMOVE lease_owner, lease_expires_at"),
		ConditionExpression:       aws.String("lease_owner = :o AND generation = :g"),
		ExpressionAttributeValues: vals,
	})
	if isConditionFailure(err) {
		return ErrLeaseLost
	}
	if err != nil {
		return opError("commit", err)
	}
	return nil
}

func (d DynamoStore) Release(ctx context.Context, owner string) error {
	_, err := d.API.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(d.Table),
		Key:                       d.key(),
		UpdateExpression:          aws.String("REMOVE lease_owner, lease_expires_at"),
		ConditionExpression:       aws.String("lease_owner = :o"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":o": s(owner)},
	})
	if err != nil && !isConditionFailure(err) {
		return opError("release", err)
	}
	return nil
}

// Seed writes a fresh grant (generation 0, no lease). Without overwrite it
// refuses to replace an existing grant.
func (d DynamoStore) Seed(ctx context.Context, g Grant, overwrite bool, now time.Time) error {
	if g.RefreshToken == "" || g.DeviceFingerprint == "" || g.FrameID == "" {
		return errors.New("seed: refresh token, fingerprint and frame id are required")
	}
	in := &dynamodb.PutItemInput{
		TableName: aws.String(d.Table),
		Item: map[string]types.AttributeValue{
			"pk": s(itemKey), "refresh_token": s(g.RefreshToken), "access_token": s(g.AccessToken),
			"access_expires_at": n(millis(g.AccessExpiresAt)), "device_fingerprint": s(g.DeviceFingerprint),
			"frame_id": s(g.FrameID), "generation": n(0), "updated_at": n(now.UnixMilli()),
		},
	}
	if !overwrite {
		in.ConditionExpression = aws.String("attribute_not_exists(pk)")
	}
	_, err := d.API.PutItem(ctx, in)
	if isConditionFailure(err) {
		return errors.New("seed: a grant is already stored (use overwrite to replace it)")
	}
	if err != nil {
		return opError("seed", err)
	}
	return nil
}
