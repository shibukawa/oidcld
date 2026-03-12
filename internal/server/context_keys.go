package server

type ctxKeyRedirectURI struct{}

var redirectURIContextKey = &ctxKeyRedirectURI{}

type ctxKeyPostLogoutRedirectURI struct{}

var postLogoutRedirectURIContextKey = &ctxKeyPostLogoutRedirectURI{}

type entraIDRequestContextKey string

const entraIDRequestInfoKey entraIDRequestContextKey = "entraid-request-info"
