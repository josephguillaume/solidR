#' @title Define Solid client using client id document
#' @param IDP Identity provider
#' @param client_id URL to Client ID document, as described in https://solid.github.io/solid-oidc/primer/#authorization-code-pkce-flow-step-7
#' @param key path to PEM key file (as written by write_pem) or an ECDSA key object. If missing, a session key will be generated using ec_keygen.
#' @seealso \link{solid_client_register_dyn}
#' @import httr2
#' @export
solid_client_register_clientid <- function(IDP,client_id,key){

  # 3. Retrieves OP Configuration
  # i.e. Fetch IDP openid configuration
  openid_config_url <- IDP
  urltools::path(openid_config_url) <- ".well-known/openid-configuration"
  configuration <- request(openid_config_url) %>%
    req_perform() %>%
    resp_body_json()

  # 12. Generates a DPoP Client Key Pair
  if(missing(key)){
    key <- openssl::ec_keygen()
  } else if(is.character(key)){
    key <- openssl::read_key(key)
  }
  stopifnot(inherits(key,"ecdsa"))


  client=oauth_client(client_id,
                      configuration$token_endpoint,
                      auth=oauth_client_req_auth_dpop,
                      key=key
  )
  client$authorization_endpoint <- configuration$authorization_endpoint
  client
}
