package go_oauth2

import (
	"crypto/rsa"
	"database/sql"
	"fmt"
	"github.com/RangelReale/osin"
	"github.com/RangelReale/osin/example"
	"github.com/dgrijalva/jwt-go"
	"github.com/felipeweb/osin-mysql"
	"github.com/gin-gonic/gin"
	"time"
)
type OauthServer struct{
	server *osin.Server
	db *sql.DB
	tokenKey []byte
	passwordAccessTypeFilter func(ctx *gin.Context)(bool,interface{})
	clientAccessTypeFilter func(ctx *gin.Context)(bool,interface{})
	customTokenTypeFilter func(ctx *gin.Context)(bool,interface{})
}

type AccessTokenGenJWT struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}


func (c *AccessTokenGenJWT) GenerateAccessToken(data *osin.AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	// generate JWT access token

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"cid": data.Client.GetId(),
		"exp": data.ExpireAt().Unix(),
		"user_data":  data.UserData,
		"time_stamp" :time.Now().Unix(),
	})

	accesstoken, err = token.SignedString(c.PrivateKey)
	if err != nil {
		return "", "", err
	}

	if !generaterefresh {
		return
	}

	// generate JWT refresh token
	token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"cid": data.Client.GetId(),
		"time_stamp" :time.Now().Unix(),
	})

	refreshtoken, err = token.SignedString(c.PrivateKey)
	if err != nil {
		return "", "", err
	}
	return
}
func newServerConfig() *osin.ServerConfig {
	return  &osin.ServerConfig{
		AuthorizationExpiration:   250,
		AccessExpiration:          3600,
		TokenType:                 "Bearer",
		AllowedAuthorizeTypes:     osin.AllowedAuthorizeType{osin.CODE,osin.TOKEN},
		AllowedAccessTypes:        osin.AllowedAccessType{osin.AUTHORIZATION_CODE,osin.PASSWORD,osin.CLIENT_CREDENTIALS},
		ErrorStatusCode:           200,
		AllowClientSecretInParams: true,
		AllowGetAccessRequest:     false,
		RetainTokenAfterRefresh:   false,
	}
}
//构造函数
func NewOauthServer(db *sql.DB,tablePrefix string,tokenKey []byte,createSchemas bool, passwordAccessTypeFilter func(ctx *gin.Context)(bool,interface{}),clientAccessTypeFilter func(ctx *gin.Context)(bool,interface{}),customTokenTypeFilter func(ctx *gin.Context)(bool,interface{})) *OauthServer{
	var oauthServer = new (OauthServer)
	oauthServer.db = db
	oauthServer.tokenKey = tokenKey
	oauthServer.passwordAccessTypeFilter = passwordAccessTypeFilter
	oauthServer.clientAccessTypeFilter = clientAccessTypeFilter
	oauthServer.customTokenTypeFilter = customTokenTypeFilter
	store := mysql.New(oauthServer.db, tablePrefix)

	if createSchemas {
		err := store.CreateSchemas()
		if err != nil {
			panic(err)
		}
	}

	server:= osin.NewServer(newServerConfig(), store);


	var accessTokenGenJWT AccessTokenGenJWT

	var err error
	if accessTokenGenJWT.PrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(oauthServer.tokenKey); err != nil {
		fmt.Printf("ERROR: %s\n", err)
		panic(err)
	}


	server.AccessTokenGen = &accessTokenGenJWT
	oauthServer.server = server
	return oauthServer
}

func (oauthServer *OauthServer)Authorize(c *gin.Context){
	resp := oauthServer.server.NewResponse()
	defer resp.Close()

	if ar := oauthServer.server.HandleAuthorizeRequest(resp, c.Request); ar != nil {
		if !example.HandleLoginPage(ar, c.Writer, c.Request) {
			return
		}
		ar.Authorized = true
		oauthServer.server.FinishAuthorizeRequest(resp, c.Request, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		fmt.Printf("ERROR: %s\n", resp.InternalError)
	}
	osin.OutputJSON(resp, c.Writer, c.Request)
}

func (oauthServer *OauthServer)CustomToken(c *gin.Context){
	resp := oauthServer.server.NewResponse()
	defer resp.Close()

	if ar := oauthServer.server.HandleAccessRequest(resp, c.Request); ar != nil {
		ar.Authorized ,ar.UserData = oauthServer.customTokenTypeFilter(c)
		oauthServer.server.FinishAccessRequest(resp, c.Request, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		fmt.Printf("ERROR: %s\n", resp.InternalError)
	}
	osin.OutputJSON(resp, c.Writer, c.Request)
}


func (oauthServer *OauthServer)Token(c *gin.Context){
	resp := oauthServer.server.NewResponse()
	defer resp.Close()

	if ar := oauthServer.server.HandleAccessRequest(resp, c.Request); ar != nil {
		//只有密码模式才需要校验密码输入是否正确，其他模式只需要用osin标准的校验逻辑
		grantType :=osin.AccessRequestType(c.Request.FormValue("grant_type"))
		ar.Authorized = true
		//var userModel  users.UserModel
		//var err error
		switch grantType {
		case osin.AUTHORIZATION_CODE:

		case osin.REFRESH_TOKEN:

		case osin.PASSWORD:
			ar.Authorized ,ar.UserData = oauthServer.passwordAccessTypeFilter(c)
		case osin.CLIENT_CREDENTIALS:
			ar.Authorized ,ar.UserData = oauthServer.clientAccessTypeFilter(c)
		case osin.ASSERTION:

		}


		oauthServer.server.FinishAccessRequest(resp, c.Request, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		fmt.Printf("ERROR: %s\n", resp.InternalError)
	}
	osin.OutputJSON(resp, c.Writer, c.Request)
}


//// Information endpoint
//http.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
//	resp := server.NewResponse()
//	defer resp.Close()
//
//	if ir := server.HandleInfoRequest(resp, r); ir != nil {
//		server.FinishInfoRequest(resp, r, ir)
//	}
//	osin.OutputJSON(resp, w, r)
//})
//
//// Application home endpoint
//http.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
//	w.Write([]byte("<html><body>"))
//	w.Write([]byte(fmt.Sprintf("<a href=\"/authorize?response_type=code&client_id=1234&state=xyz&scope=everything&redirect_uri=%s\">Login</a><br/>", url.QueryEscape("http://localhost:14000/appauth/code"))))
//	w.Write([]byte("</body></html>"))
//})
//
//// Application destination - CODE
//http.HandleFunc("/appauth/code", func(w http.ResponseWriter, r *http.Request) {
//	r.ParseForm()
//
//	code := r.FormValue("code")
//
//	w.Write([]byte("<html><body>"))
//	w.Write([]byte("APP AUTH - CODE<br/>"))
//	defer w.Write([]byte("</body></html>"))
//
//	if code == "" {
//		w.Write([]byte("Nothing to do"))
//		return
//	}
//
//	jr := make(map[string]interface{})
//
//	// build access code url
//	aurl := fmt.Sprintf("/token?grant_type=authorization_code&client_id=1234&state=xyz&redirect_uri=%s&code=%s",
//		url.QueryEscape("http://localhost:14000/appauth/code"), url.QueryEscape(code))
//
//	// if parse, download and parse json
//	if r.FormValue("doparse") == "1" {
//		err := example.DownloadAccessToken(fmt.Sprintf("http://localhost:14000%s", aurl),
//			&osin.BasicAuth{"1234", "aabbccdd"}, jr)
//		if err != nil {
//			w.Write([]byte(err.Error()))
//			w.Write([]byte("<br/>"))
//		}
//	}
//
//	// show json error
//	if erd, ok := jr["error"]; ok {
//		w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", erd)))
//	}
//
//	// show json access token
//	if at, ok := jr["access_token"]; ok {
//		w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", at)))
//	}
//
//	w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))
//
//	// output links
//	w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Goto Token URL</a><br/>", aurl)))
//
//	cururl := *r.URL
//	curq := cururl.Query()
//	curq.Add("doparse", "1")
//	cururl.RawQuery = curq.Encode()
//	w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Download Token</a><br/>", cururl.String())))
//})

