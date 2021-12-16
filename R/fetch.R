# Login to an Identity Provider and request resource from a Solid Pod using DPoP
# Following https://solid.github.io/solid-oidc/primer/

# httr2 uses req_oauth_{name} to cache access tokens from oauth_flow_{name}
# - we define req_oauth_solid_dpop
# - oauth_client has to be called manually. We instead register a client dynamically with the IDP
#   using solid_client_register_dyn
# - For the auth step, httr2 calls oauth_client_req_auth_{client$auth}.
#   We implement oauth_client_req_auth_dpop to add the dpop header and pass it as a function
# - For a request, req_perform calls auth_oauth_sign, which calls exec on the flow if needed
#   and adds a req_auth_bearer_token
#   We need a DPoP token, not Bearer token, so can't use this approach
#   Instead, req_oauth_solid_dpop invokes the authorization itself,
#   i.e. it does not wait for req_perform

# This is similar to oauth_client_req_auth_jwt_sig (auth="jwt_sig")
#  but uses a DPoP Header instead of urn:ietf:params:oauth:client-assertion-type:jwt-bearer
oauth_client_req_auth_dpop <- function(req,client){
  params <- httr2:::compact(list(client_id = client$id,client_secret=client$secret))
  #params <- httr2:::compact(list(client_id = client$id))
  key <- client$key

  # 13. Generates a DPoP Header
  jwk_pub <- jsonlite::parse_json(jose::write_jwk(key$pubkey))

  token_claim <- jose::jwt_claim(
    htu=client$token_url,
    htm="POST",
    jti=httr2:::base64_url_rand(32),
    iat=unclass(Sys.time())
  )

  token_DPoP=jose::jwt_encode_sig(
    token_claim,
    key=key,
    header=list(typ="dpop+jwt",jwk=jwk_pub)
    )

  # This will tell the OP what the client's public key is
  req <- httr2::req_headers(req,DPoP=token_DPoP)
  httr2::req_body_form(req, params)
}

#' @title OAuth authentication with authorization code
#' @param req httr2 req object
#' @param client client object, as returned by \link{solid_client_register_dyn} or \link{solid_client_register_clientid}
#' @return httr2 req object with authorization headers
#' @description Uses oauth_flow_auth_code to generate an access token,
#' used to authenticate the request with oauth_client_req_auth_dpop. The token
#' is automatically cached to minimise the number of times login/consent is performed.
#' @examples
#' \dontrun{
#' url <- "https://MY_PRIVATE_URL"
#' request(url) %>%
#'  req_oauth_solid_dpop(client) %>%
#'  req_perform() %>%
#'  resp_body_string()
#' }
#' @import httr2
#' @export
req_oauth_solid_dpop <- function(req,client){
  cache <- httr2:::cache_mem(client,key=NULL)
  # 4. Generates PKCE code challenge and code verifier
  # 5. Saves code verifier to session storage
  # 6. Authorization request
  # 9. Alice Logs In - opens browser window
  # 13. Generates a DPoP Header - auth="dpop"
  # 14. Token request with code and code verifier
  # Server does:
  # Skips 7. Fetch RP Client ID Document - uses dynamic registration instead
  # 8. Validate redirect url with Client ID Document - hardcoded in dynamic registration above
  # 10. Generate a code
  # 11. Send code to redirect url
  # 15. Validate code verifier
  # 16. Validates DPoP Token Signature
  # 17. Converts the DPoP public key to a JWK thumbprint
  # 18. Generates access token
  # 19. Generates the id_token
  # 20. Generates refresh token
  # 21. Sends tokens
  flow <- "oauth_flow_auth_code"
  flow_params = list(
    client = client,
    auth_url = client$authorization_endpoint,
    scope = "openid webid offline_access",
    port = 1410
  )

  # adapted from https://github.com/r-lib/httr2/blob/main/R/oauth.R
  token <- cache$get()
  if (is.null(token)) {
    token <- rlang::exec(flow, !!!flow_params)
  } else {
    if (httr2:::token_has_expired(token)) {
      cache$clear()
      if (is.null(token$refresh_token)) {
        token <- rlang::exec(flow, !!!flow_params)
      } else {
        token <- httr2:::token_refresh(client, token$refresh_token)
      }
    }
  }
  cache$set(token)

  # From here on is the equivalent of req_auth_bearer_token(req, token$access_token)

  key=client$key

  # Request flow starts
  # 1. An AJAX request is initiated
  # 2. Creates a DPoP header token
  request_claim <- jwt_claim(
    htu=req$url,
    htm=httr2:::req_method_get(req),
    jti=httr2:::base64_url_rand(32),
    iat=unclass(Sys.time())
  )

  jwk_pub <- jsonlite::parse_json(jose::write_jwk(key$pubkey))
  jwk_pub$alg <- "EC"
  request_dpop=jose::jwt_encode_sig(
    request_claim,
    key=key,
    header=list(typ="dpop+jwt",jwk=jwk_pub)
    )
  # 3. Sends request
  # Server does:
  # 4. Checks Access Token expirations
  # 5. Checks the DPoP token url and method
  # 5.1. (Optional) Checks DPoP token unique identifier
  # 6. Checks DPoP signature against Access Token
  # 7. Retrieves Profile
  # 8. Checks issuer
  # 9. Retrieves OP configuration
  # 10. Requests JWKS
  # 11. Checks access token signature validity
  # 12. Performs Authorization
  # 13. Returns Result
  req %>%
    req_headers(authorization=sprintf("DPoP %s",token$access_token)) %>%
    req_headers(dpop=request_dpop)
}
