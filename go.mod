module github.com/gbolo/muggle-oidc

go 1.15

require (
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/lestrrat-go/jwx v1.0.8
	github.com/nirasan/go-oauth-pkce-code-verifier v0.0.0-20170819232839-0fbfe93532da
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
	github.com/spf13/viper v1.7.1
	github.com/swaggo/http-swagger v1.0.0
	github.com/swaggo/swag v1.7.0
)

replace github.com/lestrrat-go/jwx => github.com/gbolo/jwx v1.0.9-0.20210118153205-4174a5160c4c
