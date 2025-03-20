package partycontrollers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/prov100/dc1/internal/common"
	"github.com/prov100/dc1/internal/config"
	commonproto "github.com/prov100/dc1/internal/protogen/common/v1"
	partyproto "github.com/prov100/dc1/internal/protogen/party/v1"
	"go.uber.org/zap"
)

// PartyController - Create Party Controller
type PartyController struct {
	log                *zap.Logger
	PartyServiceClient partyproto.PartyServiceClient
	UserServiceClient  partyproto.UserServiceClient
	ServerOpt          *config.ServerOptions
}

// NewPartyController - Create Party Handler
func NewPartyController(log *zap.Logger, partyServiceClient partyproto.PartyServiceClient, userServiceClient partyproto.UserServiceClient, serverOpt *config.ServerOptions) *PartyController {
	return &PartyController{
		log:                log,
		PartyServiceClient: partyServiceClient,
		UserServiceClient:  userServiceClient,
		ServerOpt:          serverOpt,
	}
}

// GetParties - used to view all Parties
func (pp *PartyController) GetParties(w http.ResponseWriter, r *http.Request) {
	fmt.Println("controllers/partycontrollers/party.go GetParties started")
	fmt.Println("controllers/partycontrollers/party.go GetParties pp.PartyServiceClient", pp.PartyServiceClient)
	requestID := common.GetRequestID()
	err := common.ValidatePermissions(w, r, []string{"parties:read"}, pp.ServerOpt.Auth0Audience, pp.ServerOpt.Auth0Domain)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, requestID)
		return
	}

	email, token := common.GetEmailToken(r)

	ctx, cdata := common.GetProtoMd(r, email, token)

	user, err := pp.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}

	cursor := r.URL.Query().Get("cursor")
	limit := r.URL.Query().Get("limit")

	parties, err := pp.PartyServiceClient.GetParties(ctx, &partyproto.GetPartiesRequest{Limit: limit, NextCursor: cursor, UserEmail: user.Email, RequestId: user.RequestId})
	if err != nil {
		pp.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Int("msgnum", 4016), zap.Error(err))
		common.RenderErrorJSON(w, "4016", err.Error(), 402, user.RequestId)
		return
	}
	fmt.Println("controllers/partycontrollers/party.go GetParties", parties)
	common.RenderJSON(w, parties)
}

// GetParty - used to view Party
func (pp *PartyController) GetParty(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID()
	err := common.ValidatePermissions(w, r, []string{"parties:read"}, pp.ServerOpt.Auth0Audience, pp.ServerOpt.Auth0Domain)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, requestID)
		return
	}

	email, token := common.GetEmailToken(r)

	ctx, cdata := common.GetProtoMd(r, email, token)

	user, err := pp.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}

	id := r.PathValue("id")

	party, err := pp.PartyServiceClient.GetParty(ctx, &partyproto.GetPartyRequest{GetRequest: &commonproto.GetRequest{Id: id, UserEmail: user.Email, RequestId: user.RequestId}})
	if err != nil {
		pp.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Int("msgnum", 4016), zap.Error(err))
		common.RenderErrorJSON(w, "4016", err.Error(), 402, user.RequestId)
		return
	}

	common.RenderJSON(w, party)
}

// CreateParty - used to Create Party
func (pp *PartyController) CreateParty(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID()
	err := common.ValidatePermissions(w, r, []string{"parties:cud"}, pp.ServerOpt.Auth0Audience, pp.ServerOpt.Auth0Domain)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, requestID)
		return
	}

	email, token := common.GetEmailToken(r)

	ctx, cdata := common.GetProtoMd(r, email, token)

	user, err := pp.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}

	form := partyproto.CreatePartyRequest{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&form)
	if err != nil {
		pp.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Int("msgnum", 4002), zap.Error(err))
		common.RenderErrorJSON(w, "4002", err.Error(), 402, user.RequestId)
		return
	}
	form.UserId = user.UserId
	form.UserEmail = user.Email
	form.RequestId = user.RequestId

	party, err := pp.PartyServiceClient.CreateParty(ctx, &form)
	if err != nil {
		pp.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Int("msgnum", 404), zap.Error(err))
		common.RenderErrorJSON(w, "4014", err.Error(), 402, user.RequestId)
		return
	}
	common.RenderJSON(w, party)
}

// UpdateParty - Update Party
func (pp *PartyController) UpdateParty(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID()
	err := common.ValidatePermissions(w, r, []string{"parties:read"}, pp.ServerOpt.Auth0Audience, pp.ServerOpt.Auth0Domain)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, requestID)
		return
	}

	email, token := common.GetEmailToken(r)

	ctx, cdata := common.GetProtoMd(r, email, token)

	user, err := pp.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}

	id := r.PathValue("id")

	form := partyproto.UpdatePartyRequest{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&form)
	if err != nil {
		pp.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Int("msgnum", 4009), zap.Error(err))
		common.RenderErrorJSON(w, "4009", err.Error(), 402, user.RequestId)
		return
	}
	form.Id = id
	form.UserId = user.UserId
	form.UserEmail = user.Email
	form.RequestId = user.RequestId
	_, err = pp.PartyServiceClient.UpdateParty(ctx, &form)
	if err != nil {
		pp.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Int("msgnum", 4016), zap.Error(err))
		common.RenderErrorJSON(w, "4016", err.Error(), 402, user.RequestId)
		return
	}
	common.RenderJSON(w, "Updated Successfully")
}

// DeleteParty - delete Party
func (pp *PartyController) DeleteParty(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID()
	err := common.ValidatePermissions(w, r, []string{"parties:read"}, pp.ServerOpt.Auth0Audience, pp.ServerOpt.Auth0Domain)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, requestID)
		return
	}

	email, token := common.GetEmailToken(r)

	ctx, cdata := common.GetProtoMd(r, email, token)

	user, err := pp.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}

	id := r.PathValue("id")

	_, err = pp.PartyServiceClient.DeleteParty(ctx, &partyproto.DeletePartyRequest{GetRequest: &commonproto.GetRequest{Id: id, UserEmail: user.Email, RequestId: user.RequestId}})
	if err != nil {
		pp.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Int("msgnum", 4016), zap.Error(err))
		common.RenderErrorJSON(w, "4016", err.Error(), 402, user.RequestId)
		return
	}
	common.RenderJSON(w, "Deleted Successfully")
}

// CreatePartyContactDetail - used to Create Party Contact
func (pp *PartyController) CreatePartyContactDetail(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID()
	err := common.ValidatePermissions(w, r, []string{"parties:read"}, pp.ServerOpt.Auth0Audience, pp.ServerOpt.Auth0Domain)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, requestID)
		return
	}

	email, token := common.GetEmailToken(r)

	ctx, cdata := common.GetProtoMd(r, email, token)

	user, err := pp.UserServiceClient.GetAuthUserDetails(ctx, &cdata)
	if err != nil {
		common.RenderErrorJSON(w, "1001", err.Error(), 401, user.RequestId)
		return
	}

	id := r.PathValue("id")

	form := partyproto.CreatePartyContactDetailRequest{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&form)
	if err != nil {
		pp.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Int("msgnum", 4004), zap.Error(err))
		common.RenderErrorJSON(w, "4004", err.Error(), 402, user.RequestId)
		return
	}
	pcid, err := strconv.ParseUint((id), 10, 0)
	if err != nil {
		pp.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Int("msgnum", 4004), zap.Error(err))
		common.RenderErrorJSON(w, "4004", err.Error(), 402, user.RequestId)
		return
	}
	form.UserId = user.UserId
	form.PartyId = uint32(pcid)
	form.UserEmail = user.Email
	form.RequestId = user.RequestId
	partyContactDetail, err := pp.PartyServiceClient.CreatePartyContactDetail(ctx, &form)
	if err != nil {
		pp.log.Error("Error", zap.String("user", user.Email), zap.String("reqid", user.RequestId), zap.Int("msgnum", 4016), zap.Error(err))
		common.RenderErrorJSON(w, "4016", err.Error(), 402, user.RequestId)
		return
	}
	common.RenderJSON(w, partyContactDetail)
}
