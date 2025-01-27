package userworkflows

import (
	"context"

	partyproto "github.com/prov100/dc1/internal/protogen/party/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

type Activities1 struct {
	UserServiceClient partyproto.UserServiceClient
}

// UpdateUserActivity - update user activity
func (a *Activities1) UpdateUserActivity(ctx context.Context, form *partyproto.UpdateUserRequest, tokenString string, user *partyproto.GetAuthUserDetailsResponse, log *zap.Logger) (string, error) {
	userServiceClient := a.UserServiceClient
	md := metadata.Pairs("authorization", "Bearer "+tokenString)
	ctxNew := metadata.NewOutgoingContext(ctx, md)
	_, err := userServiceClient.UpdateUser(ctxNew, form)
	if err != nil {
		log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		return "", err
	}
	return "Updated Successfully", nil
}

// DeleteUserActivity - delete user activity
func (a *Activities1) DeleteUserActivity(ctx context.Context, form *partyproto.DeleteUserRequest, tokenString string, user *partyproto.GetAuthUserDetailsResponse, log *zap.Logger) (string, error) {
	userServiceClient := a.UserServiceClient
	md := metadata.Pairs("authorization", "Bearer "+tokenString)
	ctxNew := metadata.NewOutgoingContext(ctx, md)
	_, err := userServiceClient.DeleteUser(ctxNew, form)
	if err != nil {
		log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		return "", err
	}
	return "Deleted Successfully", nil
}

// CreateUserActivity - create user activity
/*func (a *Activities1) CreateUserActivity(ctx context.Context, form *partyproto.CreateUserRequest, requestId string, log *zap.Logger) (*partyproto.CreateUserResponse, error) {
	userServiceClient := a.UserServiceClient
	user, err := userServiceClient.CreateUser(ctx, form)
	if err != nil {
		log.Error("Error", zap.String("reqid", requestId), zap.Error(err))
		return nil, err
	}
	return user, nil
}*/
