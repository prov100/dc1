package userworkflows

import (
	"time"

	partyproto "github.com/prov100/dc1/internal/protogen/party/v1"

	"go.uber.org/cadence/workflow"
	"go.uber.org/zap"
)

const (
	// ApplicationName is the task list
	ApplicationName = "dcsa"
)

// UpdateUserWorkflow - update user workflow
func UpdateUserWorkflow(ctx workflow.Context, form *partyproto.UpdateUserRequest, tokenString string, user *partyproto.GetAuthUserDetailsResponse, log *zap.Logger) (result string, err error) {
	ao := workflow.ActivityOptions{
		ScheduleToStartTimeout: time.Minute,
		StartToCloseTimeout:    time.Minute,
		HeartbeatTimeout:       time.Second * 20,
	}
	ctx = workflow.WithActivityOptions(ctx, ao)
	logger := workflow.GetLogger(ctx)
	var a *Activities1
	var resp string
	err = workflow.ExecuteActivity(ctx, a.UpdateUserActivity, form, tokenString, user, log).Get(ctx, &resp)
	if err != nil {
		logger.Error("Failed to UpdateUserWorkflow", zap.Error(err))
		log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		return "", err
	}
	return resp, nil
}

// DeleteUserWorkflow - delete user workflow
func DeleteUserWorkflow(ctx workflow.Context, form *partyproto.DeleteUserRequest, tokenString string, user *partyproto.GetAuthUserDetailsResponse, log *zap.Logger) (result string, err error) {
	ao := workflow.ActivityOptions{
		ScheduleToStartTimeout: time.Minute,
		StartToCloseTimeout:    time.Minute,
		HeartbeatTimeout:       time.Second * 20,
	}
	ctx = workflow.WithActivityOptions(ctx, ao)
	logger := workflow.GetLogger(ctx)
	var a *Activities1
	var resp string
	err = workflow.ExecuteActivity(ctx, a.DeleteUserActivity, form, tokenString, user, log).Get(ctx, &resp)
	if err != nil {
		logger.Error("Failed to DeleteUserWorkflow", zap.Error(err))
		log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		return "", err
	}
	return resp, nil
}

// CreateUserWorkflow - create user workflow
/*func CreateUserWorkflow(ctx workflow.Context, form *partyproto.CreateUserRequest, requestId string, log *zap.Logger) (*partyproto.CreateUserResponse, error) {
	ao := workflow.ActivityOptions{
		ScheduleToStartTimeout: time.Minute,
		StartToCloseTimeout:    time.Minute,
		HeartbeatTimeout:       time.Second * 20,
	}
	ctx = workflow.WithActivityOptions(ctx, ao)
	logger := workflow.GetLogger(ctx)
	var a *Activities1
	var user partyproto.CreateUserResponse
	err := workflow.ExecuteActivity(ctx, a.CreateUserActivity, form, requestId, log).Get(ctx, &user)
	if err != nil {
		logger.Error("Failed to CreateUserWorkflow", zap.Error(err))
		log.Error("Error", zap.String("reqid", requestId), zap.Error(err))
		return nil, err
	}
	return &user, nil
}*/
