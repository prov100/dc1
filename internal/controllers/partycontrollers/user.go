package partycontrollers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/prov100/dc1/internal/common"
	"github.com/prov100/dc1/internal/config"
	commonproto "github.com/prov100/dc1/internal/protogen/common/v1"
	partyproto "github.com/prov100/dc1/internal/protogen/party/v1"
	"github.com/prov100/dc1/internal/workflows/userworkflows"
	"google.golang.org/grpc/metadata"

	"go.uber.org/cadence/client"
	"go.uber.org/zap"
)

// UserController - used for
type UserController struct {
	log               *zap.Logger
	UserServiceClient partyproto.UserServiceClient
	wfHelper          common.WfHelper
	workflowClient    client.Client
	ServerOpt         *config.ServerOptions
}

// NewUserController - Used to create a users handler
func NewUserController(log *zap.Logger, s partyproto.UserServiceClient, wfHelper common.WfHelper, workflowClient client.Client, serverOpt *config.ServerOptions) *UserController {
	return &UserController{
		log:               log,
		UserServiceClient: s,
		wfHelper:          wfHelper,
		workflowClient:    workflowClient,
		ServerOpt:         serverOpt,
	}
}

func (uc *UserController) GetUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers")
	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers r is", r)
	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers r.Context() is", r.Context())
	requestID := common.GetRequestID()
	err := common.ValidatePermissions(w, r, []string{"users:read"}, uc.ServerOpt.Auth0Audience, uc.ServerOpt.Auth0Domain)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, requestID)
		return
	}

	email, token := common.GetEmailToken(r)

	fmt.Println("email is", email)
	fmt.Println("token is", token)

	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers call common.GetProtoMd started")
	ctx, cdata := common.GetProtoMd(r, email, token)
	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers call common.GetProtoMd ended")
	user, err := uc.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}
	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers user", user)
	users, err := uc.UserServiceClient.GetUsers(ctx, &partyproto.GetUsersRequest{UserEmail: user.Email, RequestId: user.RequestId})
	if err != nil {
		uc.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		common.RenderErrorJSON(w, "1301", err.Error(), 402, user.RequestId)
		return
	}
	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers users", users)
	common.RenderJSON(w, users)
}

func (uc *UserController) GetUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("GetUser")
	requestID := common.GetRequestID()
	err := common.ValidatePermissions(w, r, []string{"users:read"}, uc.ServerOpt.Auth0Audience, uc.ServerOpt.Auth0Domain)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, requestID)
		return
	}

	email, token := common.GetEmailToken(r)

	id := r.PathValue("id")
	fmt.Println("id in GetUser is", id)
	ctx, cdata := common.GetProtoMd(r, email, token)
	user, err := uc.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}
	fmt.Println("user", user)

	usr, err := uc.UserServiceClient.GetUser(ctx, &partyproto.GetUserRequest{GetRequest: &commonproto.GetRequest{Id: id, UserEmail: user.Email, RequestId: user.RequestId}})
	if err != nil {
		uc.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		common.RenderErrorJSON(w, "1303", err.Error(), 400, user.RequestId)
		return
	}

	common.RenderJSON(w, usr)
}

// GetUserByEmail - Get User By email
func (uc *UserController) GetUserByEmail(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID()
	err := common.ValidatePermissions(w, r, []string{"users:read"}, uc.ServerOpt.Auth0Audience, uc.ServerOpt.Auth0Domain)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, requestID)
		return
	}

	email, token := common.GetEmailToken(r)

	ctx, cdata := common.GetProtoMd(r, email, token)

	user, err := uc.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}
	form := partyproto.GetUserByEmailRequest{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&form)
	if err != nil {
		uc.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		common.RenderErrorJSON(w, "1308", err.Error(), 402, user.RequestId)
		return
	}
	form.UserEmail = user.Email
	form.RequestId = user.RequestId
	usr, err := uc.UserServiceClient.GetUserByEmail(ctx, &partyproto.GetUserByEmailRequest{Email: form.Email, UserEmail: user.Email, RequestId: user.RequestId})
	if err != nil {
		uc.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		common.RenderErrorJSON(w, "1309", err.Error(), 402, user.RequestId)
		return
	}

	common.RenderJSON(w, usr)
}

// ChangePassword - Changes Password
func (uc *UserController) ChangePassword(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID()
	err := common.ValidatePermissions(w, r, []string{"users:cud"}, uc.ServerOpt.Auth0Audience, uc.ServerOpt.Auth0Domain)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, requestID)
		return
	}

	email, token := common.GetEmailToken(r)

	ctx, cdata := common.GetProtoMd(r, email, token)

	user, err := uc.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}
	form := partyproto.ChangePasswordRequest{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&form)
	if err != nil {
		uc.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		common.RenderErrorJSON(w, "1306", err.Error(), 402, user.RequestId)
		return
	}
	form.UserEmail = user.Email
	form.RequestId = user.RequestId
	_, err = uc.UserServiceClient.ChangePassword(ctx, &form)
	if err != nil {
		uc.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		common.RenderErrorJSON(w, "1307", err.Error(), 402, user.RequestId)
		return
	}

	common.RenderJSON(w, "We've just sent you an email to reset your password.")
}

// UpdateUser - Update User
func (uc *UserController) UpdateUser(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID()
	err := common.ValidatePermissions(w, r, []string{"users:cud"}, uc.ServerOpt.Auth0Audience, uc.ServerOpt.Auth0Domain)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, requestID)
		return
	}

	email, token := common.GetEmailToken(r)

	ctx, cdata := common.GetProtoMd(r, email, token)

	id := r.PathValue("id")

	user, err := uc.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}

	md := metadata.Pairs(
		"timestamp", time.Now().Format(time.StampNano),
		"client-id", "web-api-client-us-east-1",
		"user-id", user.RequestId,
	)

	ctx = metadata.NewOutgoingContext(ctx, md)

	workflowOptions := client.StartWorkflowOptions{
		ID:                              "dcsa_" + uuid.New().String(),
		TaskList:                        userworkflows.ApplicationName,
		ExecutionStartToCloseTimeout:    time.Minute,
		DecisionTaskStartToCloseTimeout: time.Minute,
	}

	form := partyproto.UpdateUserRequest{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&form)
	if err != nil {
		uc.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		common.RenderErrorJSON(w, "1310", err.Error(), 402, user.RequestId)
		return
	}
	form.Id = id
	form.UserId = user.UserId
	form.UserEmail = user.Email
	form.RequestId = user.RequestId
	wHelper := uc.wfHelper
	result := wHelper.StartWorkflow(workflowOptions, userworkflows.UpdateUserWorkflow, &form, cdata.TokenString, user, uc.log)
	workflowClient := uc.workflowClient
	workflowRun := workflowClient.GetWorkflow(ctx, result.ID, result.RunID)
	var response string
	err = workflowRun.Get(ctx, &response)
	if err != nil {
		uc.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		common.RenderErrorJSON(w, "1310", err.Error(), 402, user.RequestId)
		return
	}
	common.RenderJSON(w, response)
}

// DeleteUser - delete user
func (uc *UserController) DeleteUser(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID()
	err := common.ValidatePermissions(w, r, []string{"users:cud"}, uc.ServerOpt.Auth0Audience, uc.ServerOpt.Auth0Domain)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, requestID)
		return
	}

	email, token := common.GetEmailToken(r)

	ctx, cdata := common.GetProtoMd(r, email, token)

	id := r.PathValue("id")

	user, err := uc.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}

	workflowOptions := client.StartWorkflowOptions{
		ID:                              "dcsa_" + uuid.New().String(),
		TaskList:                        userworkflows.ApplicationName,
		ExecutionStartToCloseTimeout:    time.Minute,
		DecisionTaskStartToCloseTimeout: time.Minute,
	}
	form := partyproto.DeleteUserRequest{UserId: id, UserEmail: user.Email, RequestId: user.RequestId}
	wHelper := uc.wfHelper
	result := wHelper.StartWorkflow(workflowOptions, userworkflows.DeleteUserWorkflow, &form, cdata.TokenString, user, uc.log)
	workflowClient := uc.workflowClient
	workflowRun := workflowClient.GetWorkflow(ctx, result.ID, result.RunID)
	var response string
	err = workflowRun.Get(ctx, &response)
	if err != nil {
		uc.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		common.RenderErrorJSON(w, "1310", err.Error(), 402, user.RequestId)
		return
	}
	common.RenderJSON(w, "response")
}
