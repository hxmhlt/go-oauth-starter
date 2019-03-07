package go_oauth2

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"net/http"
	"strings"
	"fmt"
	"time"
	"github.com/gin-gonic/gin"
)

// Strips 'TOKEN ' prefix from token string
func stripBearerPrefixFromTokenString(tok string) (string, error) {
	// Should be a bearer token
	if len(tok) > 5 && strings.ToUpper(tok[0:6]) == "BEARER" {
		return tok[7:], nil
	}

	return tok, nil
}

// Extract  token from Authorization header
// Uses PostExtractionFilter to strip "TOKEN " prefix from header
var authorizationHeaderExtractor = &request.PostExtractionFilter{
	request.HeaderExtractor{"Authorization"},
	stripBearerPrefixFromTokenString,
}

// Extractor for OAuth2 access tokens.  Looks in 'Authorization'
// header then 'access_token' argument for a token.
var myAuth2Extractor = &request.MultiExtractor{
	authorizationHeaderExtractor,
	request.ArgumentExtractor{"access_token"},
}

// A helper to write user_id and user_model to the context
func updateContextUserModel(c *gin.Context,userModel map[string]interface {} ) {
	c.Set("user_model", userModel)
}
// You can custom middlewares yourself as the doc: https://github.com/gin-gonic/gin#custom-middleware
//  r.Use(AuthMiddleware(true))
func AuthMiddleware(key []byte,auto401 bool) gin.HandlerFunc {
	return func(c *gin.Context) {


		token, err := request.ParseFromRequest(c.Request, myAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
			publickeyPEM,err:= jwt.ParseRSAPublicKeyFromPEM(key)

			return publickeyPEM, err
		})
		if err != nil {
			if auto401 {
				c.AbortWithError(http.StatusUnauthorized, err)
			}
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if(time.Now().Unix()>int64(claims["exp"].(float64))){
				if auto401 {
					c.AbortWithError(http.StatusUnauthorized, err)
				}
				fmt.Errorf("the token is expir")
				return
			}

			if claims["user_data"] != nil{
				UserModel := claims["user_data"].(map[string]interface {})
				updateContextUserModel(c,UserModel)
			}

		}
	}
}
