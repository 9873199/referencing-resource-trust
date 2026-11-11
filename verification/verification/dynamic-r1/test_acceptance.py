"""Dynamic-scope takeover and alternate-entry probes; adapters only map the frozen API."""
import pytest
from referencing import Registry,Resource
from referencing.jsonschema import DRAFT202012
import schema_adapter as api

INTERNAL='https://company.local/policy'
EXTERNAL='https://outside.local/entry'
def resource(contents):return Resource.from_contents(contents,default_specification=DRAFT202012)

def test_external_dynamic_scope_cannot_replace_trusted_dynamic_anchor():
    trusted=Registry().with_resource(INTERNAL,resource({'$id':INTERNAL,'$dynamicAnchor':'rule','const':'trusted'})).crawl()
    calls=[]
    def retrieve(uri):
        calls.append(uri)
        assert uri==EXTERNAL
        return resource({'$id':EXTERNAL,'$dynamicAnchor':'rule','$dynamicRef':INTERNAL+'#rule','const':'private-external-sample'})
    resolver=api.create(trusted,retrieve,base_uri='https://company.local/root')
    try:
        contents,child=api.lookup(resolver,EXTERNAL)
        selected,child=api.lookup_dynamic(child,contents['$dynamicRef'])
    except Exception as exc:
        assert 'private-external-sample' not in str(exc)
    else:
        assert selected.get('const')=='trusted','Trusted dynamic anchor was replaced by external dynamic scope'
    assert calls==[EXTERNAL] and len(trusted)==1
    assert trusted.contents(INTERNAL)['const']=='trusted'

def test_alternate_entry_cannot_launder_nested_trusted_identity():
    trusted=Registry().with_resource(INTERNAL,resource({'$id':INTERNAL,'$anchor':'rule','const':'trusted'})).crawl()
    original=trusted.contents(INTERNAL)
    evil={'$id':EXTERNAL,'$defs':{'part':{'$id':'https://company.local/folder/../policy#','const':'private-alias-sample'}}}
    calls=[]
    def retrieve(uri):
        calls.append(uri)
        assert uri==EXTERNAL
        return resource(evil)
    resolver=api.create(trusted,retrieve,base_uri=EXTERNAL)
    with pytest.raises(Exception) as caught:api.lookup(resolver,EXTERNAL+'#/$defs/part')
    assert 'private-alias-sample' not in str(caught.value)
    assert trusted.contents(INTERNAL) is original and len(trusted)==1

def test_revisit_same_document_via_fragment_preserves_isolated_cache():
    trusted=Registry().with_resource(INTERNAL,resource({'$id':INTERNAL,'const':'trusted'})).crawl()
    calls=[]
    def retrieve(uri):
        calls.append(uri)
        assert uri==EXTERNAL
        return resource({'$id':EXTERNAL,'$defs':{'part':{'const':'allowed'}}})
    resolver=api.create(trusted,retrieve,base_uri=EXTERNAL)
    first,child=api.lookup(resolver,EXTERNAL+'#/$defs/part')
    second,child=api.lookup(child,EXTERNAL)
    third,child=api.lookup(child,EXTERNAL+'#/$defs/part')
    assert first==third=={'const':'allowed'}
    assert second['$defs']['part']==first
    assert len(trusted)==1 and calls==[EXTERNAL]


def test_nonconflicting_dynamic_ref_really_uses_dynamic_lookup():
    trusted=Registry().with_resource(INTERNAL,resource({'$id':INTERNAL,'$dynamicAnchor':'rule','const':'trusted'})).crawl()
    calls=[]
    def retrieve(uri):
        calls.append(uri)
        assert uri==EXTERNAL
        return resource({'$id':EXTERNAL,'$dynamicAnchor':'local','const':'external-ok','$defs':{'next':{'$dynamicRef':'#local'}}})
    resolver=api.create(trusted,retrieve,base_uri=EXTERNAL)
    contents,child=api.lookup(resolver,EXTERNAL+'#/$defs/next')
    selected,child=api.lookup_dynamic(child,contents['$dynamicRef'])
    assert selected['const']=='external-ok'
    assert calls==[EXTERNAL] and len(trusted)==1


def test_ref_chain_error_records_parent_and_keyword_without_business_data():
    from referencing.exceptions import TrustBoundaryViolation
    trusted=Registry().with_resource(INTERNAL,resource({'$id':INTERNAL,'const':'trusted'})).crawl()
    entry=EXTERNAL+'/start';middle=EXTERNAL+'/middle';bad=EXTERNAL+'/bad'
    docs={entry:{'$id':entry,'$ref':'./middle'},middle:{'$id':middle,'$dynamicRef':'./bad'},bad:{'$id':INTERNAL,'examples':['BUSINESS_PAYLOAD_91C2']}}
    calls=[]
    def retrieve(uri):
        calls.append(uri)
        return resource(docs[uri])
    resolver=api.create(trusted,retrieve,base_uri=entry)
    first,child=api.lookup(resolver,entry)
    second,child=api.lookup_ref(child,first['$ref'])
    with pytest.raises(TrustBoundaryViolation) as caught:
        api.lookup_dynamic(child,second['$dynamicRef'])
    err=caught.value
    assert calls==[entry,middle,bad]
    assert len(err.path)==3
    assert err.path[-2].parent==entry and err.path[-2].via=='$ref'
    assert err.path[-1].parent==middle and err.path[-1].via=='$dynamicRef'
    assert 'BUSINESS_PAYLOAD_91C2' not in str(err) and 'BUSINESS_PAYLOAD_91C2' not in repr(err)
    assert len(trusted)==1 and trusted.contents(INTERNAL)['const']=='trusted'


def test_fetch_uri_and_declared_id_revisit_share_one_isolated_resource():
    trusted=Registry().with_resource(INTERNAL,resource({'$id':INTERNAL,'const':'trusted'})).crawl()
    canonical='https://outside.local/canonical'
    calls=[]
    def retrieve(uri):
        calls.append(uri)
        assert uri==EXTERNAL
        return resource({'$id':canonical,'$anchor':'entry','const':'allowed'})
    resolver=api.create(trusted,retrieve,base_uri=EXTERNAL)
    first,child=api.lookup(resolver,EXTERNAL)
    second,child=api.lookup(child,canonical)
    third,child=api.lookup(child,EXTERNAL+'#entry')
    assert first==second==third
    assert first['const']=='allowed' and calls==[EXTERNAL]
    assert len(trusted)==1 and trusted.contents(INTERNAL)['const']=='trusted'
