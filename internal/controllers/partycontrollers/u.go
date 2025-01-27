package partycontrollers

import (
	"net/http"

	"github.com/prov100/dc1/internal/common"
	partyproto "github.com/prov100/dc1/internal/protogen/party/v1"

	// workflows "github.com/prov100/dc1/internal/workflows"

	"go.uber.org/cadence/client"
	"go.uber.org/zap"
)

/* error message range: 1100-1299 */

// UController - create u controller
type UController struct {
	log               *zap.Logger
	UserServiceClient partyproto.UserServiceClient
	wfHelper          common.WfHelper
	workflowClient    client.Client
}

// NewUController - create u handler
func NewUController(log *zap.Logger, s partyproto.UserServiceClient, wfHelper common.WfHelper, workflowClient client.Client) *UController {
	return &UController{
		log:               log,
		UserServiceClient: s,
		wfHelper:          wfHelper,
		workflowClient:    workflowClient,
	}
}

// ServeHTTP - parse url and call controller action
func (uc *UController) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID()
	pathParts, _, err := common.ParseURL(r.URL.String())
	if err != nil {
		common.RenderErrorJSON(w, "1000", "Invalid Request", 400, requestID)
		return
	}

	switch r.Method {
	case http.MethodGet:
		uc.processGet(w, r, requestID, pathParts)
	case http.MethodPost:
		uc.processPost(w, r, requestID, pathParts)
	case http.MethodPut:
	case http.MethodDelete:
	default:
		common.RenderErrorJSON(w, "1000", "Invalid Request", 400, requestID)
		return
	}
}

// processGet - Parse URL for all the GET paths and call the controller action
/*
 GET /v1/u/confirmation/:token
 GET /v1/u/change_email/:token
*/

func (uc *UController) processGet(w http.ResponseWriter, r *http.Request, requestID string, pathParts []string) {
	switch {
	case (len(pathParts) == 4) && (pathParts[1] == "u"):
		switch {
		case pathParts[2] == "confirmation":
			// uc.ConfirmEmail(w, r, pathParts[3], requestID)
		case pathParts[2] == "change_email":
			// uc.ConfirmChangeEmail(w, r, pathParts[3], requestID)
		default:
			common.RenderErrorJSON(w, "1000", "Invalid Request", 400, requestID)
			return
		}
	default:
		common.RenderErrorJSON(w, "1000", "Invalid Request", 400, requestID)
		return
	}
}

// processPost - Parse URL for all the POST paths and call the controller action
/*
	POST /v1/u/login
	POST /v1/u/create
	POST /v1/u/forgot_password
	POST /v1/u/reset_password/:token
*/

func (uc *UController) processPost(w http.ResponseWriter, r *http.Request, requestID string, pathParts []string) {
	switch {
	case (len(pathParts) == 3) && (pathParts[1] == "u"):
		switch {
		/*case pathParts[2] == "login":
			uc.Login(w, r, requestID)
		case pathParts[2] == "create":
			uc.CreateUser(w, r, requestID)*/
		case pathParts[2] == "forgot_password":
			// uc.ForgotPassword(w, r, requestID)
		default:
			common.RenderErrorJSON(w, "1000", "Invalid Request", 400, requestID)
			return
		}
	case (len(pathParts) == 4) && (pathParts[1] == "u"):
		if pathParts[2] == "reset_password" {
			// uc.ConfirmForgotPassword(w, r, pathParts[3], requestID)
		} else {
			common.RenderErrorJSON(w, "1000", "Invalid Request", 400, requestID)
			return
		}
	default:
		common.RenderErrorJSON(w, "1000", "Invalid Request", 400, requestID)
		return
	}
}

// Login - User logins
/*func (uc *UController) Login(w http.ResponseWriter, r *http.Request, requestID string) {
	fmt.Println("UController in login")
	ctxReq := r.Context()
	ctx, cancel := context.WithTimeout(ctxReq, common.RPCReqTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		common.RenderErrorJSON(w, "1002", "Client closed connection", 402, requestID)
		return
	default:
		form := partyproto.LoginRequest{}
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&form)
		fmt.Println("UController in login form", form)
		if err != nil {
			uc.log.Error("Error",
				zap.String("reqid", requestID),
				zap.Int("msgnum", 1100),
				zap.Error(err))
			common.RenderErrorJSON(w, "1100", err.Error(), 402, requestID)
			return
		}
		form.RequestId = requestID
		fmt.Println("UController in login uc.UserServiceClient", uc.UserServiceClient)
		user, err := uc.UserServiceClient.Login(ctx, &form)
		fmt.Println("UController in login user", user)
		fmt.Println("UController in login err", err)
		if err != nil {
			uc.log.Error("Error",
				zap.String("reqid", requestID),
				zap.Int("msgnum", 1101),
				zap.Error(err))
			common.RenderErrorJSON(w, "1101", err.Error(), 402, requestID)
			return
		}
		common.RenderJSON(w, user)
	}
}*/

// ConfirmEmail - Confirmation of email
/*func (uc *UController) ConfirmEmail(w http.ResponseWriter, r *http.Request, id string, requestID string) {
	ctxReq := r.Context()
	ctx, cancel := context.WithTimeout(ctxReq, common.RPCReqTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		common.RenderErrorJSON(w, "1002", "Client closed connection", 402, requestID)
		return
	default:
		_, err := uc.UserServiceClient.ConfirmEmail(ctx, &partyproto.ConfirmEmailRequest{Token: id, RequestId: requestID})
		if err != nil {
			uc.log.Error("Error",
				zap.String("reqid", requestID),
				zap.Int("msgnum", 1102),
				zap.Error(err))
			common.RenderErrorJSON(w, "1102", err.Error(), 402, requestID)
			return
		}
		common.RenderJSON(w, "Your Account confirmed successfully")
	}
}*/

// CreateUser - Create User
/*func (uc *UController) CreateUser(w http.ResponseWriter, r *http.Request, requestID string) {
	ctxReq := r.Context()
	ctx, cancel := context.WithTimeout(ctxReq, common.RPCReqTimeout)
	defer cancel()
	fmt.Println("UController in CreateUser")
	workflowOptions := client.StartWorkflowOptions{
		ID:                              "dcsa_" + uuid.New(),
		TaskList:                        userworkflows.ApplicationName,
		ExecutionStartToCloseTimeout:    time.Minute,
		DecisionTaskStartToCloseTimeout: time.Minute,
	}

	form := partyproto.CreateUserRequest{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&form)
	if err != nil {
		uc.log.Error("Error",
			zap.String("reqid", requestID),
			zap.Int("msgnum", 1103),
			zap.Error(err))
		common.RenderErrorJSON(w, "1103", err.Error(), 402, requestID)
		return
	}
	fmt.Println("UController in CreateUser form is11111", form)
	form.HostURL = r.Host
	form.RequestId = requestID
	v := common.NewValidator()
	v.IsStrLenBetMinMax("First Name", form.FirstName, common.FirstNameLenMin, common.FirstNameLenMax)
	v.IsStrLenBetMinMax("Last Name", form.LastName, common.LastNameLenMin, common.LastNameLenMax)
	v.IsStrLenBetMinMax("Password", form.PasswordS, common.PasswordLenMin, common.PasswordLenMax)
	v.IsEmail("Email", form.Email)
	if v.IsValid() {
		common.RenderErrorJSON(w, "1110", v.Error(), 402, requestID)
		return
	}
	fmt.Println("UController in CreateUser form is2222222", form)
	wHelper := uc.wfHelper
	result := wHelper.StartWorkflow(workflowOptions, userworkflows.CreateUserWorkflow, &form, requestID, uc.log)
	fmt.Println("UController CreateUser() result is", result)
	workflowClient := uc.workflowClient
	// var workflowClient client.Client
	workflowRun := workflowClient.GetWorkflow(ctx, result.ID, result.RunID)
	fmt.Println("workflowRun", workflowRun)
	var user partyproto.CreateUserResponse
	err = workflowRun.Get(ctx, &user)
	if err != nil {
		common.RenderErrorJSON(w, "1103", err.Error(), 402, requestID)
		return
	}
	fmt.Println("user", user)
	common.RenderJSON(w, user)
}*/

// ForgotPassword - Send Link to reset password
/*func (uc *UController) ForgotPassword(w http.ResponseWriter, r *http.Request, requestID string) {
	ctxReq := r.Context()
	ctx, cancel := context.WithTimeout(ctxReq, common.RPCReqTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		common.RenderErrorJSON(w, "1002", "Client closed connection", 402, requestID)
		return
	default:
		form := partyproto.ForgotPasswordRequest{}
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&form)
		if err != nil {
			uc.log.Error("Error",
				zap.String("reqid", requestID),
				zap.Int("msgnum", 1105),
				zap.Error(err))
			common.RenderErrorJSON(w, "1105", err.Error(), 402, requestID)
			return
		}
		form.HostURL = r.Host
		form.RequestId = requestID
		_, err = uc.UserServiceClient.ForgotPassword(ctx, &form)
		if err != nil {
			uc.log.Error("Error",
				zap.String("reqid", requestID),
				zap.Int("msgnum", 1106),
				zap.Error(err))
			common.RenderErrorJSON(w, "1106", err.Error(), 402, requestID)
			return
		}

		common.RenderJSON(w, "Please Check your email and get token to reset password")
	}
}

// ConfirmForgotPassword - Reset password
func (uc *UController) ConfirmForgotPassword(w http.ResponseWriter, r *http.Request, id string, requestID string) {
	ctxReq := r.Context()
	ctx, cancel := context.WithTimeout(ctxReq, common.RPCReqTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		common.RenderErrorJSON(w, "1002", "Client closed connection", 402, requestID)
		return
	default:
		form := partyproto.ConfirmForgotPasswordRequest{}
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&form)
		if err != nil {
			uc.log.Error("Error",
				zap.String("reqid", requestID),
				zap.Int("msgnum", 1107),
				zap.Error(err))
			common.RenderErrorJSON(w, "1107", err.Error(), 402, requestID)
			return
		}
		form.Token = id
		form.RequestId = requestID
		_, err = uc.UserServiceClient.ConfirmForgotPassword(ctx, &form)
		if err != nil {
			uc.log.Error("Error",
				zap.String("reqid", requestID),
				zap.Int("msgnum", 1108),
				zap.Error(err))
			common.RenderErrorJSON(w, "1108", err.Error(), 402, requestID)
			return
		}

		common.RenderJSON(w, "Your Password Changed successfully")
	}
}

// ConfirmChangeEmail - Confirm Change Email
func (uc *UController) ConfirmChangeEmail(w http.ResponseWriter, r *http.Request, id string, requestID string) {
	ctxReq := r.Context()
	ctx, cancel := context.WithTimeout(ctxReq, common.RPCReqTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		common.RenderErrorJSON(w, "1002", "Client closed connection", 402, requestID)
		return
	default:
		_, err := uc.UserServiceClient.ConfirmChangeEmail(ctx, &partyproto.ConfirmChangeEmailRequest{Token: id, RequestId: requestID})
		if err != nil {
			uc.log.Error("Error",
				zap.String("reqid", requestID),
				zap.Int("msgnum", 1109),
				zap.Error(err))
			common.RenderErrorJSON(w, "1109", err.Error(), 402, requestID)
			return
		}
		common.RenderJSON(w, "Your Account confirmed successfully")
	}
}*/
