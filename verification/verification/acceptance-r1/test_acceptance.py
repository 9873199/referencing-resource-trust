"""Trust-boundary inputs. The adapter is bound to the frozen public API after completion."""
import pytest
from referencing import Registry,Resource
from referencing.jsonschema import DRAFT202012
import schema_adapter as api

INTERNAL='https://company.local/policy'
EXTERNAL='https://company.local/external/schema'
def resource(contents):return Resource.from_contents(contents,default_specification=DRAFT202012)
def trusted():return Registry().with_resource(INTERNAL,resource({'$id':INTERNAL,'$anchor':'rule','const':'trusted'})).crawl()

def boundary(registry,documents):
    calls=[]
    def retrieve(uri):calls.append(uri);return resource(documents[uri])
    resolver=api.create(registry,retrieve,base_uri='https://company.local/root')
    return resolver,calls

@pytest.mark.parametrize('claimed_id',[INTERNAL,'../policy',INTERNAL+'#'])
def test_external_root_cannot_claim_trusted_identity(claimed_id):
    original=trusted();resolver,calls=boundary(original,{EXTERNAL:{'$id':claimed_id,'const':'untrusted'}})
    with pytest.raises(Exception) as caught:api.lookup(resolver,EXTERNAL)
    assert calls==[EXTERNAL]
    assert 'untrusted' not in str(caught.value),'Business sample leaked into diagnostic'
    assert original.contents(INTERNAL)['const']=='trusted' and len(original)==1

def test_identical_contents_do_not_establish_trust():
    original=trusted();resolver,calls=boundary(original,{EXTERNAL:dict(original.contents(INTERNAL))})
    with pytest.raises(Exception):api.lookup(resolver,EXTERNAL)
    assert len(original)==1

def test_nested_resource_identity_cannot_shadow_trusted_resource():
    doc={'$id':EXTERNAL,'$defs':{'nested':{'$id':INTERNAL,'$dynamicAnchor':'rule','const':'private-business-sample'}}}
    original=trusted();resolver,calls=boundary(original,{EXTERNAL:doc})
    with pytest.raises(Exception) as caught:api.lookup(resolver,EXTERNAL+'#/$defs/nested')
    assert 'private-business-sample' not in str(caught.value)
    assert original.contents(INTERNAL)['const']=='trusted' and len(original)==1

def test_legitimate_external_cycle_is_not_rejected():
    a='https://outside.local/a';b='https://outside.local/b'
    original=trusted();resolver,calls=boundary(original,{a:{'$id':a,'$ref':b},b:{'$id':b,'$ref':a}})
    contents,next_resolver=api.lookup(resolver,a)
    assert contents['$ref']==b
    contents,next_resolver=api.lookup(next_resolver,b)
    assert contents['$ref']==a
    contents,next_resolver=api.lookup(next_resolver,a)
    assert contents['$ref']==b and len(original)==1

def test_separate_resolvers_do_not_share_external_state():
    uri='https://outside.local/resource';original=trusted()
    left,left_calls=boundary(original,{uri:{'$id':uri,'const':'left'}})
    right,right_calls=boundary(original,{uri:{'$id':uri,'const':'right'}})
    assert api.lookup(left,uri)[0]['const']=='left'
    assert api.lookup(right,uri)[0]['const']=='right'
    assert left_calls==[uri] and right_calls==[uri] and len(original)==1

def test_trusted_anchor_resolves_without_retrieval():
    original=trusted();resolver,calls=boundary(original,{})
    assert api.lookup(resolver,INTERNAL+'#rule')[0]['const']=='trusted'
    assert calls==[]

def test_default_registry_behavior_is_unchanged():
    original=trusted();assert original.resolver().lookup(INTERNAL+'#rule').contents['const']=='trusted'
