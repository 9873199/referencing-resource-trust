==============
Trust Boundary
==============

A `referencing.Registry` treats every resource it contains as equally trustworthy.
That is convenient for in-memory schemas, but services which resolve references into documents fetched from outside their own system then face a *confused-deputy* problem: an external document can declare an internal, trusted URI as its own :kw:`$id`, and be resolved in place of the trusted rule.

The `referencing.trust` module adds an optional boundary for exactly this situation.
It does not change the behavior of `referencing.Registry` in any way -- the boundary is opt-in and lives alongside the normal registry machinery.

A boundary is built from two pieces:

    * a *trusted* `referencing.Registry`, whose resources (including nested subresources, relative identifiers, anchors and dynamic anchors) are discovered eagerly;
    * a retrieval callable for everything else, with the same contract as the ``retrieve`` argument of `referencing.Registry`.

Resources returned by the retrieval callable are *external*.
They are admitted into an isolated layer that belongs to a single resolution, where they may reference each other, but they can never override an identity owned by the trusted registry or already claimed by another external resource in the same resolution.

.. testcode::

    from referencing import Registry, Resource, exceptions
    from referencing.trust import TrustBoundary

    trusted = Registry().with_contents(
        [
            (
                "https://rules.example.com/v1",
                {
                    "$schema": (
                        "https://json-schema.org/draft/2020-12/schema"
                    ),
                    "$id": "https://rules.example.com/v1",
                    "type": "object",
                },
            ),
        ],
    )

    documents = {
        "https://cdn.example.com/untrusted": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            # An external document claiming the identity of the trusted rule.
            "$id": "https://rules.example.com/v1",
            "type": "string",
        },
    }

    def retrieve(uri):
        return Resource.from_contents(documents[uri])

    boundary = TrustBoundary.create(trusted, retrieve)
    try:
        boundary.resolver().lookup("https://cdn.example.com/untrusted")
    except exceptions.TrustBoundaryViolation as error:
        print(error.kind)
        print(error.claimed)

.. testoutput::

    resource
    https://rules.example.com/v1

Trust is decided by *origin*, not by content.
An external document whose bytes are identical to a trusted one is still rejected, because nothing about where it came from vouches for it.

What Is Protected
-----------------

When an external resource is admitted, it and every subresource discoverable within it are checked.
The comparison normalizes identities the same way reference resolution does: relative :kw:`$id` values are resolved against the URI the document was fetched from, and fragments are removed, so an identifier ending in ``#`` cannot sneak past a check against the same URI without a fragment.

Three kinds of identity are protected:

    * **resource URIs**, including relative :kw:`$id` values that resolve onto a trusted URI, and nested subresources that do so;
    * **plain anchors**, scoped by their containing resource URI and anchor name;
    * **dynamic anchors**, protected by anchor *name* so that an external dynamic anchor cannot shadow a trusted one across the dynamic scope, even from a different resource.

An external resource may still define a plain anchor whose name is used elsewhere, because plain anchors are scoped to a resource.
Two external resources may not reuse the same dynamic-anchor name within one resolution.

Reference Paths
---------------

A `~referencing.exceptions.TrustBoundaryViolation` records how the offending resource was reached, without ever carrying the resource's contents.
Each `~referencing.exceptions.TrustBoundaryViolation.Hop` contains the parent resource URI, the reference keyword followed (``"$ref"`` or ``"$dynamicRef"``), and the fully resolved reference target.
The first hop is the entrypoint lookup and therefore has no parent or keyword.

.. testcode::

    chain = {
        "https://cdn.example.com/outer": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://cdn.example.com/outer",
            "$ref": "inner",
        },
        "https://cdn.example.com/inner": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://cdn.example.com/inner",
            "type": "integer",
        },
    }

    def retrieve_chain(uri):
        return Resource.from_contents(chain[uri])

    resolver = TrustBoundary.create(
        Registry(),
        retrieve_chain,
    ).resolver()
    outer = resolver.lookup("https://cdn.example.com/outer")
    inner = outer.resolver.lookup("inner")
    for hop in inner.resolver.path:
        print(hop.via, hop.ref)

.. testoutput::

    None https://cdn.example.com/outer
    $ref https://cdn.example.com/inner

Because only URIs and paths are recorded, business data carried inside an untrusted document cannot reach your logs through the exception.
The message of `~referencing.exceptions.TrustBoundaryViolation` is suitable for logging directly.

External References and Cycles
------------------------------

External resources can reference each other, including recursively.
A cycle is not a conflict: once a resource has been admitted, further references to it resolve against the isolated layer without another retrieval.

References from an external resource *into* the trusted registry resolve normally to the trusted contents.
The resolver returned by each lookup carries the isolated layer forward, so threading returned resolvers through a resolution (as a JSON Schema implementation does) reuses admitted resources, while a fresh `~referencing.trust.TrustBoundary.resolver` call starts from an empty layer.

The trusted registry itself is never modified.
On a conflict, no part of the offending document is admitted, and every resolver produced from the same boundary continues to see the original trusted state.

Retrieval
---------

The boundary performs no retrieval of its own and makes no network requests.
The supplied callable is the only thing that fetches anything, so a fake callable in tests can record exactly which URIs were requested.
Failures in the callable behave as they do for `referencing.Registry`: a `referencing.exceptions.NoSuchResource` propagates, while any other exception is wrapped in `referencing.exceptions.Unretrievable` and then surfaced as a `referencing.exceptions.Unresolvable` from a lookup.
