"""Report actual decisions for two RFC-equivalent URI spellings; no product patch."""
import json
from referencing import Registry,Resource
from referencing.jsonschema import DRAFT202012
from referencing.trust import TrustBoundary
internal='https://company.local/policy';external='https://outside.local/entry';alias='https://company.local/folder/../policy#'
def resource(doc):return Resource.from_contents(doc,default_specification=DRAFT202012)
trusted=Registry().with_resource(internal,resource({'$id':internal,'const':'trusted'})).crawl()
calls=[]
def retrieve(uri):
    calls.append(uri);assert uri==external
    return resource({'$id':external,'$defs':{'part':{'$id':alias,'const':'external-marker'}}})
resolver=TrustBoundary.create(trusted,retrieve).resolver()
part=resolver.lookup(external+'#/$defs/part')
by_alias=part.resolver.lookup(alias)
by_canonical=by_alias.resolver.lookup(internal)
observed={'nested_claim_admitted':True,'claimed_uri':alias,'canonical_uri':internal,'selected_through_alias':by_alias.contents['const'],'selected_through_canonical':by_canonical.contents['const'],'retrieved_uris':calls,'original_registry_length':len(trusted),'original_trusted_value':trusted.contents(internal)['const'],'interpretation':'Observed missing normalized-identity refusal, not a passing security check.'}
print(json.dumps(observed,ensure_ascii=False,indent=2))
