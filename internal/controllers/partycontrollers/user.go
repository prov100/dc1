package partycontrollers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/prov100/dc1/internal/common"
	commonproto "github.com/prov100/dc1/internal/protogen/common/v1"
	partyproto "github.com/prov100/dc1/internal/protogen/party/v1"
	userworkflows "github.com/prov100/dc1/internal/workflows/userworkflows"

	"github.com/pborman/uuid"
	"go.uber.org/cadence/client"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

// UserController - used for
type UserController struct {
	log               *zap.Logger
	UserServiceClient partyproto.UserServiceClient
	wfHelper          common.WfHelper
	workflowClient    client.Client
}

// NewUserController - Used to create a users handler
func NewUserController(log *zap.Logger, s partyproto.UserServiceClient, wfHelper common.WfHelper, workflowClient client.Client) *UserController {
	return &UserController{
		log:               log,
		UserServiceClient: s,
		wfHelper:          wfHelper,
		workflowClient:    workflowClient,
	}
}

func (uc *UserController) GetUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers")
	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers r is", r)
	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers r.Context() is", r.Context())
	x := r.Context().Value(common.KeyEmailToken)
	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers x", x)
	if ctx := r.Context().Value(common.KeyEmailToken); ctx != nil {
		fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers11111111111")
		if emailToken, ok := ctx.(common.ContextStruct); ok {
			fmt.Printf("User Email: %s", emailToken.Email)
			fmt.Printf("Token: %s", emailToken.TokenString)
		}
	}

	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers call common.GetProtoMd started")
	ctx, cdata := common.GetProtoMd(r)
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
	// common.RenderJSON(w, "users are")
}

// GetUser - Get User Details
/*func (uc *UserController) GetUser(ctx context.Context, w http.ResponseWriter, r *http.Request, id string, user *partyproto.GetAuthUserDetailsResponse) {
	usr, err := uc.UserServiceClient.GetUser(ctx, &partyproto.GetUserRequest{GetRequest: &commonproto.GetRequest{Id: id, UserEmail: user.Email, RequestId: user.RequestId}})
	if err != nil {
		uc.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		common.RenderErrorJSON(w, "1303", err.Error(), 400, user.RequestId)
		return
	}

	common.RenderJSON(w, usr)
}*/

func (uc *UserController) GetUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("GetUser")
	id := r.PathValue("id")
	fmt.Println("id in GetUser is", id)
	/*data := common.GetAuthData(r)

	cdata := partyproto.GetAuthUserDetailsRequest{}
	cdata.TokenString = data.TokenString
	cdata.Email = data.Email
	cdata.RequestUrlPath = r.URL.Path
	cdata.RequestMethod = r.Method

	md := metadata.Pairs("authorization", "Bearer "+cdata.TokenString)

	ctx := metadata.NewOutgoingContext(r.Context(), md)*/
	ctx, cdata := common.GetProtoMd(r)
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

// ChangeEmail - Changes Email
/*func (uc *UserController) ChangeEmail(ctx context.Context, w http.ResponseWriter, r *http.Request, user *partyproto.GetAuthUserDetailsResponse) {
	select {
	case <-ctx.Done():
		common.RenderErrorJSON(w, "1002", "Client closed connection", 402, user.RequestId)
		return
	default:
		form := partyproto.ChangeEmailRequest{}
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&form)
		if err != nil {
			uc.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
			common.RenderErrorJSON(w, "1304", err.Error(), 402, user.RequestId)
			return
		}
		form.HostURL = r.Host
		form.UserEmail = user.Email
		form.RequestId = user.RequestId
		_, err = uc.UserServiceClient.ChangeEmail(ctx, &form)
		if err != nil {
			uc.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
			common.RenderErrorJSON(w, "1305", err.Error(), 402, user.RequestId)
			return
		}

		common.RenderJSON(w, "Your Email Changed successfully, Please Check your email and confirm your acoount")
	}
}*/

// ChangePassword - Changes Password
func (uc *UserController) ChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx, cdata := common.GetProtoMd(r)
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

// GetUserByEmail - Get User By email
func (uc *UserController) GetUserByEmail(w http.ResponseWriter, r *http.Request) {
	ctx, cdata := common.GetProtoMd(r)
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

// UpdateUser - Update User
func (uc *UserController) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx, cdata := common.GetProtoMd(r)
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
		ID:                              "dcsa_" + uuid.New(),
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
	id := r.PathValue("id")
	ctx, cdata := common.GetProtoMd(r)
	user, err := uc.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}

	workflowOptions := client.StartWorkflowOptions{
		ID:                              "dcsa_" + uuid.New(),
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
