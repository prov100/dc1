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

// ServeHTTP - parse url and call controller action
func (uc *UserController) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	/*fmt.Println("in ServeHTTP")
	data := common.GetAuthData(r)

	cdata := partyproto.GetAuthUserDetailsRequest{}
	cdata.TokenString = data.TokenString
	cdata.Email = data.Email
	cdata.RequestUrlPath = r.URL.Path
	cdata.RequestMethod = r.Method

	md := metadata.Pairs("authorization", "Bearer "+cdata.TokenString)

	ctx := metadata.NewOutgoingContext(r.Context(), md)
	user, err := uc.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}
	pathParts, queryString, err := common.ParseURL(r.URL.String())
	if err != nil {
		common.RenderErrorJSON(w, "1000", "Invalid Request", 400, user.RequestId)
		return
	}*/
	/*switch r.Method {
	case http.MethodGet:
		uc.processGet(ctx, w, r, user, pathParts, queryString)
	case http.MethodPost:
		uc.processPost(ctx, w, r, user, pathParts)
	case http.MethodPut:
		uc.processPut(ctx, w, r, user, pathParts, data.TokenString)
	case http.MethodDelete:
		uc.processDelete(ctx, w, r, user, pathParts, data.TokenString)
	default:
		common.RenderErrorJSON(w, "1000", "Invalid Request", 400, user.RequestId)
		return
	}*/
}

// processGet - Parse URL for all the GET paths and call the controller action
/*
	GET  "/v1/users/"
	GET  "/v1/users/{id}"
*/

/*func (uc *UserController) processGet(ctx context.Context, w http.ResponseWriter, r *http.Request, user *partyproto.GetAuthUserDetailsResponse, pathParts []string, queryString url.Values) {
	switch {
	case (len(pathParts) == 2) && (pathParts[1] == "users"):
		limit := queryString.Get("limit")
		cursor := queryString.Get("cursor")
		uc.GetUsers(ctx, w, r, limit, cursor, user)
	case (len(pathParts) == 3) && (pathParts[1] == "users"):
		uc.GetUser(ctx, w, r, pathParts[2], user)
	default:
		common.RenderErrorJSON(w, "1000", "Invalid Request", 400, user.RequestId)
		return
	}
}*/

// processPost - Parse URL for all the POST paths and call the controller action
/*
	POST  "/v1/users/change-email"
	POST  "/v1/users/change-password"
	POST  "/v1/users/getuserbyemail"
*/

/*func (uc *UserController) processPost(ctx context.Context, w http.ResponseWriter, r *http.Request, user *partyproto.GetAuthUserDetailsResponse, pathParts []string) {
	switch {
	case (len(pathParts) == 3) && (pathParts[1] == "users"):
		switch {
		case pathParts[2] == "change-email":
			// uc.ChangeEmail(ctx, w, r, user)
		case pathParts[2] == "getuserbyemail":
			uc.GetUserByEmail(ctx, w, r, user)
		case pathParts[2] == "change-password":
			uc.ChangePassword(ctx, w, r, user)
		default:
			common.RenderErrorJSON(w, "1000", "Invalid Request", 400, user.RequestId)
			return
		}
	default:
		common.RenderErrorJSON(w, "1000", "Invalid Request", 400, user.RequestId)
		return
	}
}*/

// processPut - Parse URL for all the put paths and call the controller action
/*
 PUT  "/v1/users/{id}"
*/

/*func (uc *UserController) processPut(ctx context.Context, w http.ResponseWriter, r *http.Request, user *partyproto.GetAuthUserDetailsResponse, pathParts []string, tokenString string) {
	if (len(pathParts) == 3) && (pathParts[1] == "users") {
		uc.UpdateUser(ctx, w, r, pathParts[2], user, tokenString)
	} else {
		common.RenderErrorJSON(w, "1000", "Invalid Request", 400, user.RequestId)
		return
	}
}*/

// processDelete - Parse URL for all the delete paths and call the controller action
/*
 DELETE  "/v1/users/{id}"
*/

/*func (uc *UserController) processDelete(ctx context.Context, w http.ResponseWriter, r *http.Request, user *partyproto.GetAuthUserDetailsResponse, pathParts []string, tokenString string) {
	if (len(pathParts) == 3) && (pathParts[1] == "users") {
		uc.DeleteUser(ctx, w, r, pathParts[2], user, tokenString)
	} else {
		common.RenderErrorJSON(w, "1000", "Invalid Request", 400, user.RequestId)
		return
	}
}*/

// GetUsers - Get Users
/*func (uc *UserController) GetUsers(ctx context.Context, w http.ResponseWriter, r *http.Request, limit string, cursor string, user *partyproto.GetAuthUserDetailsResponse) {
	users, err := uc.UserServiceClient.GetUsers(ctx, &partyproto.GetUsersRequest{UserEmail: user.Email, RequestId: user.RequestId})
	if err != nil {
		uc.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Error(err))
		common.RenderErrorJSON(w, "1301", err.Error(), 402, user.RequestId)
		return
	}
	common.RenderJSON(w, users)
}*/

func (uc *UserController) GetUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers")
	/*data := common.GetAuthData(r)

	cdata := partyproto.GetAuthUserDetailsRequest{}
	cdata.TokenString = data.TokenString
	cdata.Email = data.Email
	cdata.RequestUrlPath = r.URL.Path
	cdata.RequestMethod = r.Method

	md := metadata.Pairs("authorization", "Bearer "+cdata.TokenString)

	ctx := metadata.NewOutgoingContext(r.Context(), md)*/
	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers r is", r)
	fmt.Println("controllers/partycontrollrs/user.go UserController GetUsers r.Context() is", r.Context())
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
