#' @title Parse RDF dataset from Solid server
#' @param docs One or more URLs to fetch from Solid server(s)
#' @param ... not used
#' @param rdf optional existing rdflib rdf store
#' @param client client object, as returned by solid_client_register_dyn
#' @return parsed triples in the form of an rdf object containing the redland world and model objects
#' @import httr2
#' @import rdflib
#' @import redland
#' @export
rdf_parse_solid <- function(docs,...,rdf=NULL,client){
  reqs<-lapply(docs,function(doc) request(doc) %>%
                 req_oauth_solid_dpop(client) %>%
                 #TODO: does not work for NSS as it doesn't send ETag for text/turtle
                 #TODO: customise path?
                 req_cache(path=tempdir())
  )
  resps <- multi_req_perform(reqs)
  fail <- vapply(resps, inherits, "error", FUN.VALUE = logical(1))
  stopifnot(!any(fail))
  # TODO: handle http errors
  contents <- lapply(resps,resp_body_string)
  # Using redland directly because rdflib::rdf_parse writes to file first,
  #  and there's a bug in redland https://github.com/ropensci/redland-bindings/issues/94
  #rdf_parse(content,...,format="turtle",base=doc)
  if (is.null(rdf)) {
    rdf <- rdflib::rdf()
  }
  #TODO: support other than turtle
  format="turtle"
  mimetype="text/turtle"
  parser <- new("Parser", rdf$world, name = format, mimeType = mimetype)
  for(i in seq_along(docs)){
    doc <- docs[i]
    content <- contents[[i]]
    librdf_uri <- redland::librdf_new_uri(rdf$world@librdf_world, doc)
    status <- redland::librdf_parser_parse_string_into_model(parser@librdf_parser,content,librdf_uri,rdf$model@librdf_model)
    stopifnot(all(status==0))
  }
  rdf
}
