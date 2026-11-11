"""API and result-shape mapping only; all decisions remain in referencing.trust."""
from referencing.trust import TrustBoundary

def create(registry,retrieve,base_uri=''):
    return TrustBoundary.create(registry,retrieve).resolver(base_uri=base_uri)

def lookup(resolver,reference):
    result=resolver.lookup(reference)
    return result.contents,result.resolver

def lookup_ref(resolver,reference):
    result=resolver.lookup(reference,via='$ref')
    return result.contents,result.resolver

def lookup_dynamic(resolver,reference):
    result=resolver.lookup_dynamic(reference)
    return result.contents,result.resolver
