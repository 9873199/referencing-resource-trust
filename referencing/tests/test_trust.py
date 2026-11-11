"""
Tests for the optional external-resource trust boundary.

The untrusted documents below deliberately carry a business sample string;
every rejection path is asserted not to leak it, since these exceptions are
the thing an application is likely to log.
"""

import logging

import pytest

from referencing import Registry, Resource, exceptions
from referencing.jsonschema import DRAFT202012
from referencing.trust import BoundResolver, TrustBoundary

SCHEMA_URI = "https://json-schema.org/draft/2020-12/schema"

TRUSTED_URI = "https://internal.example.com/rules/v1"
TRUSTED_CHILD_URI = "https://internal.example.com/rules/sub"
EXT_URI = "https://ext.example.com/schema"

#: A stand-in for sensitive business data carried inside untrusted input.
SECRET = "BUSINESS-SAMPLE-SECRET-VALUE-42"


def schema(**kwargs):
    return {"$schema": SCHEMA_URI, **kwargs}


class FakeRetriever:
    """
    A retrieval callable with no network access, recording fetched URIs.
    """

    def __init__(self, documents):
        self.documents = documents
        self.calls = []

    def __call__(self, uri):
        self.calls.append(uri)
        return Resource.from_contents(self.documents[uri])


def blow_up(uri):  # pragma: no cover - asserted never to be called
    raise AssertionError(f"unexpected retrieval of {uri!r}")


@pytest.fixture
def trusted_registry():
    return Registry().with_contents(
        [
            (
                TRUSTED_URI,
                schema(
                    **{
                        "$id": TRUSTED_URI,
                        "$anchor": "known",
                        "$dynamicAnchor": "meta",
                        "type": "object",
                        "marker": SECRET,
                    },
                ),
            ),
            (
                TRUSTED_CHILD_URI,
                schema(
                    **{
                        "$id": TRUSTED_CHILD_URI,
                        "$defs": {
                            "leaf": {"$anchor": "leaf", "type": "integer"},
                        },
                    },
                ),
            ),
        ],
    )


@pytest.fixture
def trusted_snapshot(trusted_registry):
    """
    The full state of the trusted registry before any boundary resolution.
    """
    crawled = trusted_registry.crawl()
    return (
        dict(crawled._resources),
        dict(crawled._anchors),
        set(crawled._uncrawled),
    )


def assert_trusted_untouched(registry, snapshot):
    crawled = registry.crawl()
    assert (
        dict(crawled._resources),
        dict(crawled._anchors),
        set(crawled._uncrawled),
    ) == snapshot


class TestTrustedAccess:
    def test_trusted_resource_resolves_without_retrieval(
        self,
        trusted_registry,
    ):
        boundary = TrustBoundary.create(trusted_registry, blow_up)
        resolved = boundary.resolver().lookup(TRUSTED_URI)
        assert resolved.contents["type"] == "object"

    def test_trusted_anchor_and_dynamic_anchor(self, trusted_registry):
        resolver = TrustBoundary.create(
            trusted_registry,
            blow_up,
        ).resolver()
        resolved = resolver.lookup(f"{TRUSTED_URI}#known")
        assert resolved.contents["$anchor"] == "known"

        dynamic = resolver.lookup_dynamic(f"{TRUSTED_URI}#meta")
        assert dynamic.contents["$dynamicAnchor"] == "meta"

    def test_eager_crawl_discovers_nested_trusted_identity(
        self,
        trusted_registry,
    ):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{"$id": TRUSTED_CHILD_URI, "type": "string"},
                ),
            },
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            boundary.resolver().lookup(EXT_URI)
        assert exc_info.value.kind == "resource"
        assert exc_info.value.claimed == TRUSTED_CHILD_URI
        assert retriever.calls == [EXT_URI]


class TestResourceSpoofing:
    def test_external_id_claiming_trusted_uri_is_rejected(
        self,
        trusted_registry,
    ):
        retriever = FakeRetriever(
            {EXT_URI: schema(**{"$id": TRUSTED_URI, "type": "string"})},
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            boundary.resolver().lookup(EXT_URI)

        error = exc_info.value
        assert error.kind == exceptions.TrustBoundaryViolation.RESOURCE
        assert error.claimed == TRUSTED_URI
        assert error.ref == EXT_URI
        assert retriever.calls == [EXT_URI]

    def test_identical_contents_do_not_confer_trust(self, trusted_registry):
        # The fetched bytes are exactly the trusted document, but their
        # origin is external, so origin -- not content -- decides trust.
        retriever = FakeRetriever(
            {EXT_URI: dict(trusted_registry[TRUSTED_URI].contents)},
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            boundary.resolver().lookup(EXT_URI)
        assert exc_info.value.kind == "resource"
        assert exc_info.value.claimed == TRUSTED_URI

    def test_empty_fragment_identity_is_normalized(self, trusted_registry):
        retriever = FakeRetriever(
            {EXT_URI: schema(**{"$id": TRUSTED_URI + "#"})},
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            boundary.resolver().lookup(EXT_URI)
        assert exc_info.value.claimed == TRUSTED_URI

    def test_relative_id_is_resolved_against_fetch_uri(self):
        documents = {
            "https://cdn.example.com/external/v1/doc": schema(
                **{"$id": "doc", "type": "integer"},
            ),
        }
        retriever = FakeRetriever(documents)
        boundary = TrustBoundary.create(Registry(), retriever)
        resolved = boundary.resolver().lookup(
            "https://cdn.example.com/external/v1/doc",
        )
        expected = "https://cdn.example.com/external/v1/doc"
        assert expected in resolved.resolver.layer
        assert (
            resolved.contents
            == documents["https://cdn.example.com/external/v1/doc"]
        )

    def test_relative_traversal_into_trusted_path_is_rejected(
        self,
        trusted_registry,
    ):
        # A trusted resource also lives under the external origin, so a
        # relative $id traversal can reach a trusted identity.
        trusted = trusted_registry.with_contents(
            [
                (
                    "https://cdn.example.com/internal/rule",
                    schema(**{"$id": "https://cdn.example.com/internal/rule"}),
                ),
            ],
        )
        retriever = FakeRetriever(
            {
                "https://cdn.example.com/external/dir/doc": schema(
                    **{
                        "$id": "doc",
                        "$defs": {
                            "child": {"$id": "../../internal/rule"},
                        },
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(trusted, retriever)
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            boundary.resolver().lookup(
                "https://cdn.example.com/external/dir/doc",
            )
        assert exc_info.value.kind == "resource"
        assert exc_info.value.claimed == (
            "https://cdn.example.com/internal/rule"
        )

    def test_nested_subresource_squats_trusted_identity(
        self,
        trusted_registry,
    ):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{
                        "$id": EXT_URI,
                        "$defs": {
                            "evil": {
                                "$id": TRUSTED_URI,
                                "type": "string",
                                "marker": SECRET,
                            },
                        },
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            boundary.resolver().lookup(EXT_URI)
        assert exc_info.value.kind == "resource"
        assert exc_info.value.claimed == TRUSTED_URI
        assert SECRET not in str(exc_info.value)

    def test_subresource_cannot_claim_root_fetch_uri(self):
        # The root is indexed under the URI it was fetched from even when
        # its internal $id differs, so a nested subresource must not be
        # allowed to claim that fetch URI.
        fetch_uri = "https://cdn.example.com/v2/doc"
        retriever = FakeRetriever(
            {
                fetch_uri: schema(
                    **{
                        "$id": "https://ext.example.com/real-id",
                        "$defs": {"hijack": {"$id": fetch_uri}},
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            boundary.resolver().lookup(fetch_uri)
        assert exc_info.value.kind == "resource"
        assert exc_info.value.claimed == fetch_uri

    def test_subresource_cannot_claim_root_internal_id(self):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{
                        "$id": EXT_URI,
                        "$defs": {"hijack": {"$id": EXT_URI}},
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            boundary.resolver().lookup(EXT_URI)
        assert exc_info.value.kind == "resource"
        assert exc_info.value.claimed == EXT_URI


class TestAnchorProtection:
    def test_plain_anchor_same_name_other_uri_is_allowed(
        self,
        trusted_registry,
    ):
        # Plain anchors are scoped to (URI, name); the same name elsewhere
        # is a different anchor and must remain usable.
        retriever = FakeRetriever(
            {EXT_URI: schema(**{"$id": EXT_URI, "$anchor": "known"})},
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        resolved = boundary.resolver().lookup(f"{EXT_URI}#known")
        assert resolved.contents["$anchor"] == "known"

    def test_duplicate_plain_anchor_within_document_is_rejected(self):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{
                        "$id": EXT_URI,
                        "$defs": {
                            "one": {"$anchor": "twin"},
                            "two": {"$anchor": "twin"},
                        },
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            boundary.resolver().lookup(EXT_URI)
        assert exc_info.value.kind == "anchor"
        assert exc_info.value.claimed == f"{EXT_URI}#twin"

    def test_dynamic_anchor_shadowing_trusted_name_is_rejected(
        self,
        trusted_registry,
    ):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{
                        "$id": EXT_URI,
                        "$dynamicAnchor": "meta",
                        "marker": SECRET,
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            boundary.resolver().lookup(EXT_URI)
        error = exc_info.value
        assert error.kind == "dynamicAnchor"
        assert error.claimed == f"{EXT_URI}#meta"
        assert SECRET not in str(error)

    def test_dynamic_anchor_name_collision_between_external_docs(self):
        other_uri = "https://ext.example.com/other"
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{"$id": EXT_URI, "$dynamicAnchor": "shared"},
                ),
                other_uri: schema(
                    **{"$id": other_uri, "$dynamicAnchor": "shared"},
                ),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        resolver = boundary.resolver()
        first = resolver.lookup(EXT_URI)
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            first.resolver.lookup(other_uri)
        assert exc_info.value.kind == "dynamicAnchor"
        assert exc_info.value.claimed == f"{other_uri}#shared"

    def test_duplicate_dynamic_anchor_within_document_is_rejected(self):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{
                        "$id": EXT_URI,
                        "$defs": {
                            "one": {"$dynamicAnchor": "dup"},
                            "two": {"$dynamicAnchor": "dup"},
                        },
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            boundary.resolver().lookup(EXT_URI)
        assert exc_info.value.kind == "dynamicAnchor"


class TestExternalResolution:
    def test_external_resource_is_admitted_to_layer(self):
        retriever = FakeRetriever(
            {EXT_URI: schema(**{"$id": EXT_URI, "type": "integer"})},
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        resolved = boundary.resolver().lookup(EXT_URI)
        assert resolved.resolver.layer[EXT_URI].contents["type"] == "integer"
        assert retriever.calls == [EXT_URI]

    def test_fetch_uri_and_internal_id_are_both_resolvable(self):
        internal = "https://ext.example.com/real-id"
        retriever = FakeRetriever(
            {"https://cdn.example.com/v2/doc": schema(**{"$id": internal})},
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        resolved = boundary.resolver().lookup(
            "https://cdn.example.com/v2/doc",
        )
        layer = resolved.resolver.layer
        assert "https://cdn.example.com/v2/doc" in layer
        assert internal in layer

        # Either spelling now resolves without another retrieval.
        again = resolved.resolver.lookup(internal)
        assert again.resolver.layer is layer
        assert retriever.calls == ["https://cdn.example.com/v2/doc"]

    def test_relative_reference_between_external_resources(self):
        documents = {
            "https://ext.example.com/dir/entry": schema(
                **{"$id": "entry", "$ref": "../shared/v1"},
            ),
            "https://ext.example.com/shared/v1": schema(
                **{"$id": "https://ext.example.com/shared/v1", "const": 7},
            ),
        }
        retriever = FakeRetriever(documents)
        boundary = TrustBoundary.create(Registry(), retriever)
        entry = boundary.resolver().lookup(
            "https://ext.example.com/dir/entry",
        )
        shared = entry.resolver.lookup("../shared/v1")
        assert (
            shared.contents == documents["https://ext.example.com/shared/v1"]
        )
        assert retriever.calls == [
            "https://ext.example.com/dir/entry",
            "https://ext.example.com/shared/v1",
        ]

    def test_external_reference_into_trusted_resource(
        self,
        trusted_registry,
    ):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{
                        "$id": EXT_URI,
                        "properties": {"rule": {"$ref": TRUSTED_URI}},
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        external = boundary.resolver().lookup(EXT_URI)
        trusted = external.resolver.lookup(TRUSTED_URI)
        assert trusted.contents["type"] == "object"
        # The trusted resource was already present, so nothing was fetched
        # for it.
        assert retriever.calls == [EXT_URI]

    def test_pointer_and_anchor_fragments(self):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{
                        "$id": EXT_URI,
                        "$defs": {
                            "a": {"$anchor": "named", "const": 42},
                        },
                        "properties": {"deep": {"const": 7}},
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        resolver = boundary.resolver().lookup(EXT_URI).resolver
        assert resolver.lookup("#/properties/deep").contents == {"const": 7}
        assert resolver.lookup("#named").contents == {
            "$anchor": "named",
            "const": 42,
        }

    def test_pointer_to_nowhere_is_preserved(self):
        retriever = FakeRetriever(
            {EXT_URI: schema(**{"$id": EXT_URI, "properties": {}})},
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        resolver = boundary.resolver().lookup(EXT_URI).resolver
        with pytest.raises(exceptions.PointerToNowhere):
            resolver.lookup("#/nope/missing")

    def test_no_such_anchor_is_preserved(self):
        retriever = FakeRetriever(
            {EXT_URI: schema(**{"$id": EXT_URI})},
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        resolver = boundary.resolver().lookup(EXT_URI).resolver
        with pytest.raises(exceptions.NoSuchAnchor):
            resolver.lookup("#missing")

    def test_cyclic_references_between_external_resources_are_allowed(self):
        uri_a = "https://ext.example.com/a"
        uri_b = "https://ext.example.com/b"
        retriever = FakeRetriever(
            {
                uri_a: schema(
                    **{
                        "$id": uri_a,
                        "properties": {"b": {"$ref": uri_b}},
                    },
                ),
                uri_b: schema(
                    **{
                        "$id": uri_b,
                        "properties": {"a": {"$ref": uri_a}},
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        first = boundary.resolver().lookup(uri_a)
        second = first.resolver.lookup(uri_b)
        third = second.resolver.lookup(uri_a)
        assert third.contents == first.contents
        # Cycles resolve against the isolated layer; no repeated fetches.
        assert retriever.calls == [uri_a, uri_b]

    def test_self_referential_external_document(self):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{
                        "$id": EXT_URI,
                        "$defs": {
                            "node": {
                                "$anchor": "node",
                                "properties": {"next": {"$ref": "#node"}},
                            },
                        },
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        resolver = boundary.resolver().lookup(EXT_URI).resolver
        node = resolver.lookup("#node")
        again = node.resolver.lookup("#node")
        assert again.contents == node.contents
        assert retriever.calls == [EXT_URI]

    def test_opaque_resources_are_supported(self):
        contents = {"whatever": True}
        calls = []

        def retrieve(uri):
            calls.append(uri)
            return Resource.opaque(contents)

        boundary = TrustBoundary.create(Registry(), retrieve)
        resolved = boundary.resolver().lookup(EXT_URI)
        assert resolved.contents == contents
        # An opaque resource has no internal identifier, so it is indexed
        # only under the URI it was fetched from.
        assert list(resolved.resolver.layer) == [EXT_URI]
        assert calls == [EXT_URI]

    def test_missing_resource_is_unresolvable(self):
        def retrieve(uri):
            raise exceptions.NoSuchResource(ref=uri)

        boundary = TrustBoundary.create(Registry(), retrieve)
        with pytest.raises(exceptions.Unresolvable) as exc_info:
            boundary.resolver().lookup("urn:missing")
        assert exc_info.value.ref == "urn:missing"

    def test_retrieval_failure_is_wrapped(self):
        def retrieve(uri):
            raise RuntimeError("simulated outage")

        boundary = TrustBoundary.create(Registry(), retrieve)
        with pytest.raises(exceptions.Unresolvable):
            boundary.resolver().lookup("urn:boom")

    def test_cannot_determine_specification_passes_through(self):
        def retrieve(uri):
            return Resource.from_contents({})

        boundary = TrustBoundary.create(Registry(), retrieve)
        with pytest.raises(exceptions.CannotDetermineSpecification):
            boundary.resolver().lookup(EXT_URI)


class TestDynamicReferences:
    def test_external_dynamic_ref_resolves(self):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{
                        "$id": EXT_URI,
                        "$dynamicAnchor": "leaf",
                        "const": 1,
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        external = boundary.resolver().lookup(EXT_URI)
        resolved = external.resolver.lookup_dynamic("#leaf")
        assert resolved.contents["$dynamicAnchor"] == "leaf"
        assert resolved.resolver.path[-1].via == "$dynamicRef"

    def test_dynamic_ref_to_plain_anchor_is_rejected(self):
        retriever = FakeRetriever(
            {EXT_URI: schema(**{"$id": EXT_URI, "$anchor": "plain"})},
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        resolver = boundary.resolver().lookup(EXT_URI).resolver
        with pytest.raises(exceptions.NoSuchAnchor):
            resolver.lookup_dynamic("#plain")

    def test_dynamic_ref_with_pointer_fragment_acts_like_plain_lookup(self):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{"$id": EXT_URI, "properties": {"deep": {"const": 9}}},
                ),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        resolver = boundary.resolver().lookup(EXT_URI).resolver
        resolved = resolver.lookup_dynamic("#/properties/deep")
        assert resolved.contents == {"const": 9}

    def test_dynamic_ref_without_fragment_returns_whole_resource(self):
        retriever = FakeRetriever(
            {EXT_URI: schema(**{"$id": EXT_URI, "const": 3})},
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        resolver = boundary.resolver().lookup(EXT_URI).resolver
        resolved = resolver.lookup_dynamic(EXT_URI)
        assert resolved.contents["const"] == 3

    def test_dynamic_ref_to_missing_resource_is_unresolvable(self):
        def retrieve(uri):
            raise exceptions.NoSuchResource(ref=uri)

        boundary = TrustBoundary.create(Registry(), retrieve)
        with pytest.raises(exceptions.Unresolvable):
            boundary.resolver().lookup_dynamic("urn:missing#leaf")

    def test_dynamic_ref_retrieval_failure_is_wrapped(self):
        def retrieve(uri):
            raise RuntimeError("simulated outage")

        boundary = TrustBoundary.create(Registry(), retrieve)
        with pytest.raises(exceptions.Unresolvable):
            boundary.resolver().lookup_dynamic("urn:boom#leaf")

    def test_dynamic_scope_pairs_uris_with_combined_view(
        self,
        trusted_registry,
    ):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{"$id": EXT_URI, "$ref": TRUSTED_URI},
                ),
            },
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        external = boundary.resolver().lookup(EXT_URI)
        scoped = external.resolver.lookup(TRUSTED_URI)
        scope = list(scoped.resolver.dynamic_scope())
        assert [uri for uri, _registry in scope] == [EXT_URI]
        combined = dict(scope[0][1])
        assert TRUSTED_URI in combined
        assert EXT_URI in combined


class TestPathRecording:
    def test_entrypoint_hop(self):
        retriever = FakeRetriever(
            {EXT_URI: schema(**{"$id": EXT_URI})},
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        resolved = boundary.resolver().lookup(EXT_URI)
        (hop,) = resolved.resolver.path
        assert hop == exceptions.TrustBoundaryViolation.Hop(
            parent=None,
            via=None,
            ref=EXT_URI,
        )

    def test_ref_chain_records_every_hop(self, trusted_registry):
        middle_uri = "https://ext.example.com/middle"
        squat_uri = "https://ext.example.com/squat"
        retriever = FakeRetriever(
            {
                EXT_URI: schema(**{"$id": EXT_URI, "$ref": "./middle"}),
                middle_uri: schema(
                    **{"$id": middle_uri, "$ref": "squat"},
                ),
                squat_uri: schema(**{"$id": TRUSTED_URI, "marker": SECRET}),
            },
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        entry = boundary.resolver().lookup(EXT_URI)
        middle = entry.resolver.lookup(entry.contents["$ref"])
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            middle.resolver.lookup(middle.contents["$ref"])

        path = exc_info.value.path
        assert [hop.via for hop in path] == [None, "$ref", "$ref"]
        assert [hop.parent for hop in path] == [
            None,
            EXT_URI,
            middle_uri,
        ]
        assert [hop.ref for hop in path] == [
            EXT_URI,
            middle_uri,
            squat_uri,
        ]
        assert SECRET not in str(exc_info.value)
        assert SECRET not in repr(exc_info.value)

    def test_fragment_ref_inside_document_is_labeled_ref(self):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{
                        "$id": EXT_URI,
                        "$defs": {"a": {"$anchor": "named"}},
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        resolved = (
            boundary.resolver()
            .lookup(EXT_URI)
            .resolver.lookup(
                "#named",
            )
        )
        assert resolved.resolver.path[-1].via == "$ref"

    def test_explicit_via_keyword_is_recorded(self):
        retriever = FakeRetriever(
            {EXT_URI: schema(**{"$id": EXT_URI})},
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        resolver = boundary.resolver().lookup(EXT_URI).resolver
        resolved = resolver.lookup("#", via="$ref")
        assert resolved.resolver.path[-1].via == "$ref"

    def test_error_message_is_log_safe(self, caplog, trusted_registry):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{"$id": TRUSTED_URI, "sample": SECRET},
                ),
            },
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        with caplog.at_level(logging.ERROR):
            try:
                boundary.resolver().lookup(EXT_URI)
            except exceptions.TrustBoundaryViolation as error:
                logging.getLogger("test").error("rejected: %s", error)
            else:  # pragma: no cover
                pytest.fail("boundary did not reject the spoofing document")
        assert TRUSTED_URI in caplog.text
        assert SECRET not in caplog.text


class TestIsolation:
    def test_failure_leaves_no_partial_layer(self, trusted_registry):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(
                    **{
                        "$id": EXT_URI,
                        "$defs": {"evil": {"$id": TRUSTED_URI}},
                    },
                ),
            },
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        resolver = boundary.resolver()
        with pytest.raises(exceptions.TrustBoundaryViolation):
            resolver.lookup(EXT_URI)
        assert resolver.layer == Registry()

    def test_resolvers_have_independent_layers(self):
        other_uri = "https://ext.example.com/other"
        retriever = FakeRetriever(
            {
                EXT_URI: schema(**{"$id": EXT_URI}),
                other_uri: schema(**{"$id": other_uri}),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        first = boundary.resolver().lookup(EXT_URI)
        second = boundary.resolver().lookup(other_uri)
        assert list(first.resolver.layer) == [EXT_URI]
        assert list(second.resolver.layer) == [other_uri]

    def test_two_resolvers_share_trusted_registry(
        self,
        trusted_registry,
        trusted_snapshot,
    ):
        boundary = TrustBoundary.create(trusted_registry, blow_up)
        first = boundary.resolver()
        second = boundary.resolver()
        assert isinstance(first, BoundResolver)
        assert first._boundary is second._boundary

        first.lookup(TRUSTED_URI)
        second.lookup(f"{TRUSTED_URI}#known")
        assert_trusted_untouched(trusted_registry, trusted_snapshot)

    def test_rejections_never_mutate_trusted_registry(
        self,
        trusted_registry,
        trusted_snapshot,
    ):
        retriever = FakeRetriever(
            {
                EXT_URI: schema(**{"$id": TRUSTED_URI}),
                "https://ext.example.com/anchor": schema(
                    **{"$id": EXT_URI, "$dynamicAnchor": "meta"},
                ),
            },
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        for uri in retriever.documents:
            with pytest.raises(exceptions.TrustBoundaryViolation):
                boundary.resolver().lookup(uri)
        assert_trusted_untouched(trusted_registry, trusted_snapshot)
        # Nothing external was admitted into the trusted view.
        assert len(trusted_registry.crawl()) == 2

    def test_two_external_documents_cannot_share_an_identity(self):
        # Distinct fetch URIs whose documents declare the same internal id.
        source_a = "https://a.example.com/doc"
        source_b = "https://b.example.com/doc"
        shared = "urn:shared:v1"
        retriever = FakeRetriever(
            {
                source_a: schema(**{"$id": shared}),
                source_b: schema(**{"$id": shared}),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        first = boundary.resolver().lookup(source_a)
        with pytest.raises(exceptions.TrustBoundaryViolation) as exc_info:
            first.resolver.lookup(source_b)
        assert exc_info.value.kind == "resource"
        assert exc_info.value.claimed == shared

        # The first binding still wins and resolves to the first document.
        again = first.resolver.lookup(shared)
        assert again.contents is retriever.documents[source_a]
        assert set(first.resolver.layer) == {source_a, shared}

    def test_same_document_reentered_via_another_entrypoint(self):
        gateway = "https://ext.example.com/gateway"
        other_entry = "https://ext.example.com/other-entry"
        shared = "https://ext.example.com/shared/v1"
        retriever = FakeRetriever(
            {
                gateway: schema(**{"$id": gateway, "$ref": "shared/v1"}),
                other_entry: schema(
                    **{"$id": other_entry, "$ref": "shared/v1"},
                ),
                shared: schema(**{"$id": shared, "type": "integer"}),
            },
        )
        boundary = TrustBoundary.create(Registry(), retriever)
        session = boundary.resolver()
        session = session.lookup(gateway).resolver
        session = session.lookup(shared).resolver
        session = session.lookup(other_entry).resolver
        again = session.lookup(shared)

        # Threading the resolver forward reuses the isolated layer, so the
        # shared document is fetched exactly once.
        assert retriever.calls == [gateway, shared, other_entry]
        assert set(again.resolver.layer) == {gateway, other_entry, shared}

        # A fresh resolution starts from an empty layer and re-fetches.
        fresh = boundary.resolver().lookup(shared)
        assert list(fresh.resolver.layer) == [shared]
        assert retriever.calls[-1] == shared

    def test_in_subresource_moves_base_uri(self):
        child = DRAFT202012.create_resource(
            schema(**{"$id": "child/"}),
        )
        boundary = TrustBoundary.create(Registry(), blow_up)
        resolver = boundary.resolver(base_uri="https://ext.example.com/root/")
        moved = resolver.in_subresource(child)
        assert moved.base_uri == "https://ext.example.com/root/child/"
        # Without an identifier the resolver is unchanged.
        assert resolver.in_subresource(Resource.opaque({})) is resolver

    def test_as_plain_resolver_combines_views(self, trusted_registry):
        retriever = FakeRetriever(
            {EXT_URI: schema(**{"$id": EXT_URI})},
        )
        boundary = TrustBoundary.create(trusted_registry, retriever)
        resolved = boundary.resolver().lookup(EXT_URI)
        plain = resolved.resolver.as_plain_resolver()
        assert plain._base_uri == EXT_URI
        assert TRUSTED_URI in plain._registry
        assert EXT_URI in plain._registry
