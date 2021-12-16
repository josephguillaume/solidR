
#' @title Register dynamic client
#' @param IDP Identity provider
#' @seealso \link{solid_client_register_clientid}
#' @import httr2
#' @export
solid_client_register_dyn <- function(IDP){

  # 3. Retrieves OP Configuration
  # i.e. Fetch IDP openid configuration
  openid_config_url <- IDP
  urltools::path(openid_config_url) <- ".well-known/openid-configuration"
  configuration <- request(openid_config_url) %>%
    req_perform() %>%
    resp_body_json()

  # Dynamic client registration
  rego <- request(configuration$registration_endpoint) %>%
    req_body_json(list(application_type = "web",
                       redirect_uris = list("http://localhost:1410/"),
                       subject_type = "public",
                       token_endpoint_auth_method = "client_secret_basic",
                       id_token_signed_response_alg = "RS256",
                       grant_types = list("authorization_code", "refresh_token","urn:ietf:params:oauth:grant-type:device_code")
                       #grant_types = list("authorization_code", "refresh_token")
    )) %>%
    req_perform %>%
    resp_body_json()


  # 12. Generates a DPoP Client Key Pair
  key <- openssl::ec_keygen()

  client <- oauth_client(rego$client_id,
                         configuration$token_endpoint,
                         secret=rego$client_secret,
                         auth=oauth_client_req_auth_dpop,
                         key=key
  )
  client$authorization_endpoint <- configuration$authorization_endpoint
  client
}
