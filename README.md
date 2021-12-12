R package to interact with a Solid server: https://solidproject.org/

It uses the [httr2](https://github.com/r-lib/httr2/) package to implement the Solid-OIDC OAuth flow. See: 
https://solid.github.io/solid-oidc/primer/

Example:
```R
client <- solid_client_register_dyn("https://solidcommunity.net")
request(url) %>%
 req_oauth_solid_dpop(client) %>%
 req_perform() %>%
 resp_body_string()
```

Some higher level functions are also provided:

- `rdf_parse_solid` returns parsed triples in an rdflib rdf object


This package was created for personal use and is unmaintained.

There are no plans to make it available on CRAN. If you wish to maintain this package, feel free to fork it. If you notify me, I'll include a link to the maintained version here.
