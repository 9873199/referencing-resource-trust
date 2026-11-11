"""Separate verification console using the frozen library's real boundary API."""
import argparse,importlib.util,importlib.metadata,traceback
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--scenario',choices=['identity','nested','dynamic','isolation'],required=True);a=p.parse_args()
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
root=Path(__file__).parent
checks=module('boundary_checks',root/'test_acceptance.py')
dynamic=module('dynamic_checks',root.parent/'dynamic-r1/test_acceptance.py')
print('Library: referencing '+importlib.metadata.version('referencing'))
print('Resource loading: local callback, no network service')
print('Trusted registry and per-resolution external layer')
try:
    if a.scenario=='identity':
        for claimed in (checks.INTERNAL,'../policy',checks.INTERNAL+'#'):
            checks.test_external_root_cannot_claim_trusted_identity(claimed)
        checks.test_identical_contents_do_not_establish_trust()
        print('External root identity claims: refused')
        print('Identical document contents: no extra trust granted')
    elif a.scenario=='nested':
        checks.test_nested_resource_identity_cannot_shadow_trusted_resource()
        print('Nested resource identity claim: refused')
        dynamic.test_alternate_entry_cannot_launder_nested_trusted_identity()
        print('Alternate URI spelling: refused')
    elif a.scenario=='dynamic':
        dynamic.test_external_dynamic_scope_cannot_replace_trusted_dynamic_anchor()
        print('Trusted dynamic anchor: protected')
        dynamic.test_nonconflicting_dynamic_ref_really_uses_dynamic_lookup()
        print('Nonconflicting dynamic reference: resolved')
        dynamic.test_ref_chain_error_records_parent_and_keyword_without_business_data()
        print('Reference chain diagnostics: parent and keyword retained; samples excluded')
    else:
        checks.test_legitimate_external_cycle_is_not_rejected()
        checks.test_separate_resolvers_do_not_share_external_state()
        dynamic.test_revisit_same_document_via_fragment_preserves_isolated_cache()
        dynamic.test_fetch_uri_and_declared_id_revisit_share_one_isolated_resource()
        print('Legitimate cycle and repeated fragment lookup: resolved')
        print('Fetch URI and declared ID: one isolated resource')
        print('Two independent resolvers: isolated; trusted registry unchanged')
    print('Observed check: PASS')
except Exception:
    traceback.print_exc();print('Observed check: FAIL');raise SystemExit(1)
