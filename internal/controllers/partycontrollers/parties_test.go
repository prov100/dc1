package partycontrollers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/prov100/dc1/internal/common"
	commonproto "github.com/prov100/dc1/internal/protogen/common/v1"
	partyproto "github.com/prov100/dc1/internal/protogen/party/v1"
	"github.com/prov100/dc1/test"
	_ "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
)

func TestGetParty(t *testing.T) {
	err := test.LoadSQL(log, dbService)
	if err != nil {
		t.Error(err)
		return
	}

	tokenString, _ := LoginUser()

	w := httptest.NewRecorder()

	req, err := http.NewRequest("GET", "https://localhost:6060/v0.1/parties/be5bc290-7bac-48bb-a211-f3fa5a3ab3ae/", nil)
	if err != nil {
		t.Error(err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+tokenString)
	mux.ServeHTTP(w, req)

	resp := w.Result()
	// Check the status code is what we expect.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Unexpected status code %d", resp.StatusCode)
		return
	}
	fmt.Println("resp", resp)
	fmt.Println("w.w.Body.String()", w.Body.String())
	fmt.Println("w.Body.Bytes()", w.Body.Bytes())

	partyResponse := &partyproto.GetPartyResponse{}
	err = json.Unmarshal(w.Body.Bytes(), partyResponse)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("partyResponse", partyResponse)

	party, err := GetParty(uint32(8), []byte{190, 91, 194, 144, 123, 172, 72, 187, 162, 17, 243, 250, 90, 58, 179, 174}, "be5bc290-7bac-48bb-a211-f3fa5a3ab3ae", "Asseco Denmark", "CVR-25645774", "CVR-25645774", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkFzaW", uint32(8), "active", "2019-07-23T10:04:26Z", "2019-07-23T10:04:26Z", "auth0|66fd06d0bfea78a82bb42459", "auth0|66fd06d0bfea78a82bb42459")
	if err != nil {
		t.Error(err)
		return
	}
	expected := &partyproto.GetPartyResponse{}
	expected.Party = party

	fmt.Println("expected", expected)

	if !reflect.DeepEqual(partyResponse, expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			partyResponse, expected)
		return
	}
}

func GetParty(id uint32, uuid4 []byte, idS string, partyName string, taxReference1 string, taxReference2 string, publicKey string, addressId uint32, statusCode string, createdAt string, updatedAt string, createdByUserId string, updatedByUserId string) (*partyproto.Party, error) {
	createdAt1, err := common.ConvertTimeToTimestamp(Layout, createdAt)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8301), zap.Error(err))
	}

	updatedAt1, err := common.ConvertTimeToTimestamp(Layout, updatedAt)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8301), zap.Error(err))
	}

	partyD := new(partyproto.PartyD)
	partyD.Id = id
	partyD.Uuid4 = uuid4
	partyD.IdS = idS
	partyD.PartyName = partyName
	partyD.TaxReference1 = taxReference1
	partyD.TaxReference2 = taxReference2
	partyD.PublicKey = publicKey
	partyD.AddressId = addressId

	crUpdTime := new(commonproto.CrUpdTime)
	crUpdTime.CreatedAt = createdAt1
	crUpdTime.UpdatedAt = updatedAt1

	crUpdUser := new(commonproto.CrUpdUser)
	crUpdUser.StatusCode = "active"
	crUpdUser.CreatedByUserId = createdByUserId
	crUpdUser.UpdatedByUserId = updatedByUserId

	party := partyproto.Party{PartyD: partyD, CrUpdUser: crUpdUser, CrUpdTime: crUpdTime}
	return &party, nil
}
