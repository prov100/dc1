package partycontrollers

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"go.uber.org/zap"

	"github.com/prov100/dc1/internal/common"
	"github.com/prov100/dc1/internal/config"
	partyservices "github.com/prov100/dc1/internal/services/partyservices"
	"github.com/prov100/dc1/internal/workers/userworkers"
	"github.com/prov100/dc1/test"

	"github.com/throttled/throttled/v2/store/goredisstore"
)

var (
	dbService    *common.DBService
	redisService *common.RedisService
	// userServiceClient partyproto.UserServiceClient
	mailerService common.MailerIntf
	jwtOpt        *config.JWTOptions
	// userOpt       *config.UserOptions
	userTestOpt *config.UserTestOptions
	mux         *http.ServeMux
	log         *zap.Logger
	logUser     *zap.Logger
	logParty    *zap.Logger
	Layout      string
)

func TestMain(m *testing.M) {
	var err error
	v, err := config.GetViper()
	if err != nil {
		os.Exit(1)
	}
	configFilePath := v.GetString("SC_DCSA_WORKFLOW_CONFIG_FILE_PATH")

	logOpt, err := config.GetLogConfig(v)
	if err != nil {
		os.Exit(1)
	}

	log = config.SetUpLogging(logOpt.Path)
	logUser = config.SetUpLogging(logOpt.UserPath)
	logParty = config.SetUpLogging(logOpt.PartyPath)
	Layout = "2006-01-02T15:04:05Z"

	dbOpt, err := config.GetDbConfig(log, v, true, "SC_DCSA_DB", "SC_DCSA_DBHOST", "SC_DCSA_DBPORT", "SC_DCSA_DBUSER_TEST", "SC_DCSA_DBPASS_TEST", "SC_DCSA_DBNAME_TEST", "SC_DCSA_DBSQL_MYSQL_TEST", "SC_DCSA_DBSQL_MYSQL_SCHEMA", "SC_DCSA_DBSQL_MYSQL_TRUNCATE", "SC_DCSA_DBSQL_PGSQL_TEST", "SC_DCSA_DBSQL_PGSQL_SCHEMA", "SC_DCSA_DBSQL_PGSQL_TRUNCATE")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8301), zap.Error(err))
		return
	}

	jwtOpt, err = config.GetJWTConfig(log, v, true, "SC_DCSA_JWT_KEY_TEST", "SC_DCSA_JWT_DURATION_TEST")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8301), zap.Error(err))
		return
	}

	/*elasticOpt, err := config.GetElasticConfig(log, v, true, "VILOM_ELASTIC_USER", "VILOM_ELASTIC_PASS", "VILOM_ELASTIC_SERVER", "VILOM_ELASTIC_INDEXNAME_TEST")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8301), zap.Error(err))
		return
	}*/

	/*rateOpt, err := config.GetRateConfig(log, v)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8301), zap.Error(err))
		os.Exit(1)
	}*/

	userTestOpt, err = config.GetUserTestConfig(log, v)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8301), zap.Error(err))
		return
	}

	// redisOpt, mailerOpt, grpcServerOpt, _, _, jaegerTracerOpt, _, roleOpt := config.GetConfigOpt(log, v)

	// dbService, redisService, _, tokenService = common.GetServices(log, true, dbOpt, redisOpt, jwtOpt, mailerOpt)

	redisOpt, mailerOpt, serverOpt, grpcServerOpt, oauthOpt, userOpt, uptraceOpt := config.GetConfigOpt(log, v)

	dbService, redisService, _ = common.GetServices(log, true, dbOpt, redisOpt, jwtOpt, mailerOpt)

	mailerService, err = test.CreateMailerServiceTest(log)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8016), zap.Error(err))
	}

	pwd, _ := os.Getwd()
	go partyservices.StartUserServer(logUser, true, pwd, dbOpt, redisOpt, mailerOpt, serverOpt, grpcServerOpt, jwtOpt, oauthOpt, userOpt, uptraceOpt, dbService, redisService, mailerService)
	go partyservices.StartPartyServer(logParty, true, pwd, dbOpt, redisOpt, mailerOpt, grpcServerOpt, jwtOpt, oauthOpt, userOpt, uptraceOpt, dbService, redisService, mailerService)
	go userworkers.StartUserWorker(log, true, pwd, grpcServerOpt, uptraceOpt, configFilePath)

	store, err := goredisstore.New(redisService.RedisClient, "throttled:")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8601), zap.Error(err))
		return
	}
	// userServiceClient = partyproto.NewUserServiceClient(userconn)
	mux = http.NewServeMux()
	err = InitTest(log, mux, store, serverOpt, grpcServerOpt, uptraceOpt, configFilePath)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8602), zap.Error(err))
		return
	}
	os.Exit(m.Run())
}

func LoginUser() (string, string) {
	fmt.Println("in Login User userTestOpt.Tokenstring", userTestOpt.Tokenstring)
	return userTestOpt.Tokenstring, ""
}

/*func LoginUser() (string, string) {
	w := httptest.NewRecorder()

	// req, err := http.NewRequest("POST", "https://localhost:8000/v0.1/u/login", bytes.NewBuffer([]byte(`{"Email": ` + userTestOpt.Email +, `"Password": ` + userTestOpt.Password + `}`)))
	fmt.Println("LoginUser()")
	req, err := http.NewRequest("POST", "https://localhost:8000/v0.1/u/login", bytes.NewBuffer([]byte(`{"Email": "sprov100@gmail.com", "Password": "abc1238"}`)))
	fmt.Println("LoginUser() req", req)
	fmt.Println("LoginUser() err", err)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8603), zap.Error(err))
		return "", ""
	}
	mux.ServeHTTP(w, req)
	fmt.Println("LoginUser() w.Body", w.Body)
	user := partyproto.LoginResponse{}
	decoder := json.NewDecoder(strings.NewReader(w.Body.String()))
	err = decoder.Decode(&user)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8604), zap.Error(err))
		return "", ""
	}
	fmt.Println("LoginUser() user", user)
	return user.AccessToken, user.RefreshToken
}*/

/*func LoginUser() (string, string) {
	domain := "dev-llzybv0gk4ybnuqm.us.auth0.com"
	clientID := "xStBKcCvjs9cCXgyvAxn0202D5MwtyDV"
	clientSecret := "NEzc11dTF_Kka5EQZN6Kp9HvQOTZGyOjeX9XCdstpvR4xtafR4oeaqifAvnAPn8-"
	audience := "https://hello-world.example.com"

	// Initialize a new client using a domain, client ID and client secret.
	authAPI, err := authentication.New(
		context.TODO(), // Replace with a Context that better suits your usage
		domain,
		authentication.WithClientID(clientID),
		authentication.WithClientSecret(clientSecret), // Optional depending on the grants used
	)
	if err != nil {
		fmt.Println("failed to initialize the auth0 authentication API client", err)
	}
	accessToken, err := LoginWithClientCredentials(authAPI, clientSecret, audience)
	fmt.Println("LoginUser() accessToken", accessToken)
	fmt.Println("LoginUser() err is", err)
	if err != nil {
		fmt.Println("err", err)
		return "", ""
	}

	return accessToken, ""
}*/

/*func LoginWithClientCredentials(authAPI *authentication.Authentication, clientSecret string, audience string) (string, error) {
	tokenSet, err := authAPI.OAuth.LoginWithClientCredentials(context.Background(), oauth.LoginWithClientCredentialsRequest{
		ClientAuthentication: oauth.ClientAuthentication{
			ClientSecret: clientSecret,
		},
		Audience: audience,
	}, oauth.IDTokenValidationOptions{})
	if err != nil {
		fmt.Println("LoginWithClientCredentials err", err)
		return "", err
	}
	fmt.Println("tokenSet", tokenSet)
	fmt.Println("tokenSet.Scope", tokenSet.Scope)
	fmt.Println("tokenSet.AccessToken", tokenSet.AccessToken)
	fmt.Println("tokenSet.TokenType", tokenSet.TokenType)

	return tokenSet.AccessToken, nil
}*/

/*func GetUserByEmail(email string) (*userproto.User, error) {
	db := dbService.DB
	user := userproto.User{}
	row := db.QueryRow(`select
    uuid4,
    password_reset_token,
    new_email_reset_token,
		email from users where email = ? and statusc = ?;`, email, common.Active)

	err := row.Scan(
		&user.Uuid4,
		&user.PasswordResetToken,
		&user.NewEmailResetToken,
		&user.Email)

	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8605), zap.Error(err))
		return nil, err
	}
	uuid4Str, err := common.UUIDBytesToStr(user.Uuid4)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8606), zap.Error(err))
		return nil, err
	}
	user.IdS = uuid4Str
	return &user, nil
}*/
