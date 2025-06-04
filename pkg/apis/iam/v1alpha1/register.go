package v1alpha1

import (
	"errors"
	"net/http"

	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/constants"

	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
)

var ModuleVersion = runtime.ModuleVersion{Name: "iam", Version: "v1alpha1"}

var (
	iamTags = []string{"iam"}

	userTags = []string{"users"}
)

func AddToContainer(c *restful.Container, addCallback func(func() error, func() error)) error {
	ws := runtime.NewWebService(ModuleVersion)
	handler := New()

	// TODO:hysyeah
	/*	ws.Route(ws.POST("/login").
		To(handler.handleUserLogin).
		Doc("Login user, get the JWT token.").
		Metadata(restfulspec.KeyOpenAPITags, iamTags).
		Reads(UserPassword{}).
		Produces(restful.MIME_JSON).
		Returns(http.StatusOK, "", response.Response{}))*/
	//
	ws.Route(ws.POST("/refresh-token").
		To(handler.handleRefreshToken).
		Doc("Refresh JWT token.").
		Metadata(restfulspec.KeyOpenAPITags, iamTags).
		Reads(PostRefreshToken{}, "Refresh Token").
		Produces(restful.MIME_JSON).
		Returns(http.StatusOK, "", response.Response{}))
	//
	//ws.Route(ws.POST("/logout").
	//	To(handler.handleUserLogOut).
	//	Doc("Logout user.").
	//	Metadata(restfulspec.KeyOpenAPITags, iamTags).
	//	Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
	//	Returns(http.StatusOK, "", response.Header{}))
	// TODO:hysyeah

	ws.Route(ws.GET("/users").
		To(handler.handleListUsers).
		Doc("List users.").
		Metadata(restfulspec.KeyOpenAPITags, userTags).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Produces(restful.MIME_JSON).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.GET("/users/{user}").
		To(handler.handleDescribeUser).
		Doc("Retrieve user details.").
		Metadata(restfulspec.KeyOpenAPITags, userTags).
		Param(ws.PathParameter("user", "user name").DataType("string").Required(true)).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Produces(restful.MIME_JSON).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.GET("/users/{user}/status").
		To(handler.handleUserStatus).
		Doc("Retrieve user creating or deleting status.").
		Metadata(restfulspec.KeyOpenAPITags, userTags).
		Param(ws.PathParameter("user", "user name").DataType("string").Required(true)).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Produces(restful.MIME_JSON).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.GET("/users/{user}/login-records").
		To(handler.handleListUserLoginRecords).
		Doc("List user login records.").
		Metadata(restfulspec.KeyOpenAPITags, userTags).
		Param(ws.PathParameter("user", "user name").DataType("string").Required(true)).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Produces(restful.MIME_JSON).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.POST("/users").
		To(handler.handleCreateUser).
		Doc("Create user.").
		Metadata(restfulspec.KeyOpenAPITags, userTags).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Reads(UserCreate{}).
		Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.DELETE("/users/{user}").
		To(handler.handleDeleteUser).
		Doc("Delete user.").
		Metadata(restfulspec.KeyOpenAPITags, userTags).
		Param(ws.PathParameter("user", "delete user name").DataType("string").Required(true)).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Produces(restful.MIME_JSON).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.PUT("/users/{user}/password").
		To(handler.handleResetUserPassword).
		Doc("Reset user password.").
		Metadata(restfulspec.KeyOpenAPITags, userTags).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter("user", "user name").DataType("string").Required(true)).
		Reads(PasswordReset{}).
		Produces(restful.MIME_JSON).
		Returns(http.StatusOK, "Reset password", response.Response{}))

	ws.Route(ws.PUT("/users/{user}/limits").
		To(handler.handleUpdateUserLimits).
		Reads(UserResourceLimit{}).
		Doc("update user's limits.").
		Metadata(restfulspec.KeyOpenAPITags, userTags).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter("user", "user name").DataType("string").Required(true)).
		Reads(UserResourceLimit{}).
		Produces(restful.MIME_JSON).
		Returns(http.StatusOK, "Reset password", response.Response{}))

	ws.Route(ws.GET("/users/{user}/metrics").
		To(handler.handleGetUserMetrics).
		Doc("get user's metrics").
		Metadata(restfulspec.KeyOpenAPITags, userTags).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter("user", "user name").DataType("string").Required(true)).
		Produces(restful.MIME_JSON).
		Returns(http.StatusOK, "get user's metrics", nil))

	ws.Route(ws.GET("/roles").
		To(handler.handleListUserRoles).
		Doc("List user roles.").
		Metadata(restfulspec.KeyOpenAPITags, userTags).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Produces(restful.MIME_JSON).
		Returns(http.StatusOK, "", response.Response{}))
	// TODO:hysyeah
	//ws.Route(ws.POST("/validate").
	//	To(handler.handleValidateUserPassword).
	//	Doc("validate user.").
	//	Metadata(restfulspec.KeyOpenAPITags, iamTags).
	//	Reads(UserPassword{}).
	//	Produces(restful.MIME_JSON).
	//	Returns(http.StatusOK, "", response.Response{}))
	// TODO:hysyeah

	c.Add(ws)

	// add user creating event to backup callback
	addCallback(
		func() error { // phase backup-new
			if handler.isUserCreating() {
				return errors.New("user createing")
			}

			handler.lockUserCreating()
			return nil
		},

		func() error { // phase backup-finished
			handler.unlockUserCreating()
			return nil
		},
	)
	return nil
}
