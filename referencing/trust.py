"""
An optional resource trust boundary for externally loaded resources.

The normal `referencing.Registry` behavior is unchanged: anything added to a
registry is considered equally trustworthy, and a retrieved resource may
claim whatever URI it likes via its internal identifier.

For services that resolve references into schemas fetched from outside their
trust boundary, that behavior allows a confused-deputy style attack: an
external document can give itself the ``$id`` of an internal, trusted rule
and then be resolved in place of it.

This module provides an opt-in boundary:

    * the caller explicitly declares a *trusted* registry, whose resources,
      subresources, anchors and dynamic anchors are fully discovered up
      front;
    * resources reached through the supplied retrieval callable are kept in
      an ephemeral, per-resolution isolated layer which shadows nothing;
    * an external resource may not claim a URI, anchor or dynamic anchor
      that already belongs to the trusted set, nor one that another external
      resource reached during the same resolution has already claimed;
    * references between external resources (including recursive / cyclic
      ones) resolve normally against the isolated layer;
    * the trusted registry object itself is never mutated, and on a conflict
      the error records the reference path (parent resource, ``$ref`` or
      ``$dynamicRef`` keyword, resolved target) without ever carrying the
      untrusted document's contents, so business samples cannot leak into
      logs.

No network access is performed here -- retrieval remains entirely the
caller's responsibility via the supplied callable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Generic, cast
from urllib.parse import urldefrag, urljoin

from attrs import evolve, field
from rpds import List

from referencing import exceptions
from referencing._attrs import frozen
from referencing._core import (
    EMPTY_UNCRAWLED,
    Registry,
    Resolved,
    Resolver,
    Resource,
)
from referencing.typing import URI, Anchor as AnchorType, D, Retrieve

if TYPE_CHECKING:
    from collections.abc import Iterable

#: The JSON Schema reference keywords recognized when recording paths.
REF = "$ref"
DYNAMIC_REF = "$dynamicRef"


def _normalize(uri: URI) -> URI:
    """
    Normalize a resource identity for comparison.

    The fragment is removed, as a fragment identifies a location *within* a
    resource rather than the resource itself, and trailing empty fragments
    (``...#``) are equivalent to no fragment. The remaining identity is
    absolutized so that relative references and equivalent spellings
    collapse together.
    """
    without_fragment, _ = urldefrag(uri)
    return urljoin(without_fragment, "")


def _resolve_ref(base_uri: URI, ref: URI) -> tuple[URI, str]:
    """
    Resolve a possibly-relative reference against a base URI.

    Returns the fragment-free target resource identity and the raw
    fragment (without its leading ``#``), applying exactly the reference
    normalization a `referencing.Resolver` applies.
    """
    if ref.startswith("#"):
        return base_uri, ref[1:]
    return urldefrag(urljoin(base_uri, ref))


def _is_dynamic_anchor(anchor: AnchorType[D]) -> bool:
    # Imported lazily so custom, non-JSON-Schema specifications do not
    # depend on the JSON Schema module. Unknown anchor types are treated as
    # plain anchors, which are still protected.
    from referencing.jsonschema import DynamicAnchor

    return isinstance(anchor, DynamicAnchor)


def _as_plain(resolver: BoundResolver[D]) -> Resolver[D]:
    """
    View a `BoundResolver` as the structural `Resolver` the spec layer uses.

    `BoundResolver` deliberately mirrors the surface of `Resolver` (base
    URI, combined registry view and dynamic scope), and the pointer and
    anchor machinery only invokes those shared methods, never
    `Resolver`-specific internals.
    """
    return cast("Resolver[D]", resolver)


def _resources_of(registry: Registry[D]):
    return registry._resources


def _anchors_of(registry: Registry[D]):
    return registry._anchors  # type: ignore[reportPrivateUsage]


@frozen
class _TrustedSnapshot(Generic[D]):
    """
    The eagerly discovered identities owned by the trusted registry.
    """

    registry: Registry[D]
    uris: frozenset[URI]
    anchors: frozenset[tuple[URI, str]]
    dynamic_anchor_names: frozenset[str]

    @classmethod
    def from_registry(cls, registry: Registry[D]) -> _TrustedSnapshot[D]:
        crawled = registry.crawl()
        anchors: set[tuple[URI, str]] = set()
        dynamic_names: set[str] = set()
        for (uri, name), anchor in _anchors_of(crawled).items():
            if _is_dynamic_anchor(anchor):
                dynamic_names.add(name)
            else:
                anchors.add((uri, name))
        return cls(
            registry=crawled,
            uris=frozenset(_resources_of(crawled)),
            anchors=frozenset(anchors),
            dynamic_anchor_names=frozenset(dynamic_names),
        )


@frozen
class TrustBoundary(Generic[D]):
    """
    An opt-in trust boundary around a trusted `Registry`.

    Resources already present in the trusted registry form the trusted
    identity set, which is discovered eagerly (including nested
    subresources, relative identifiers, plain anchors and dynamic
    anchors). Resources reached via the retrieval callable are external
    and untrusted; they live only in the isolated layer of a single
    resolution and can never override a trusted identity or an identity
    already claimed by another external resource in the same resolution.

    Build one with `TrustBoundary.create`, then call `resolver` to obtain
    a boundary-enforcing `BoundResolver`.
    """

    _trusted: _TrustedSnapshot[D] = field(alias="trusted")
    _retrieve: Retrieve[D] = field(alias="retrieve")

    @classmethod
    def create(
        cls,
        trusted: Registry[D],
        retrieve: Retrieve[D],
    ) -> TrustBoundary[D]:
        """
        Build a boundary, eagerly crawling the trusted registry.

        Arguments:

            trusted:
                the registry containing only resources the caller vouches
                for. It is crawled once and never modified.

            retrieve:
                a callable used to fetch external resources, with the same
                contract as the ``retrieve`` argument of `Registry`. No
                retrieval is performed by this module; pass a fake in tests
                to record which URIs are fetched.

        Raises:

            `referencing.exceptions.TrustBoundaryViolation`

                whenever an externally retrieved resource (including its
                subresources, anchors and dynamic anchors) claims an
                identity it is not allowed to define.

        """
        return cls(
            trusted=_TrustedSnapshot.from_registry(trusted),
            retrieve=retrieve,
        )

    def resolver(self, base_uri: URI = "") -> BoundResolver[D]:
        """
        Return a resolver which enforces this trust boundary.
        """
        return BoundResolver(
            base_uri=base_uri,
            boundary=self,
            layer=Registry(),
            previous=List(),
            path=(),
        )


@frozen
class BoundResolver(Generic[D]):
    """
    A reference resolver bound to a `TrustBoundary`.

    It mirrors the public surface of `referencing.Resolver` -- ``lookup``,
    ``in_subresource`` and ``dynamic_scope`` -- so it can be handed to code
    written against a normal resolver (including the JSON Schema anchor
    machinery), while every externally reached resource is admitted through
    the boundary.
    """

    _base_uri: URI = field(alias="base_uri")
    _boundary: TrustBoundary[D] = field(alias="boundary")
    _layer: Registry[D] = field(alias="layer")
    _previous: List[URI] = field(default=List(), repr=False, alias="previous")
    _path: tuple[exceptions.TrustBoundaryViolation.Hop, ...] = field(
        default=(),
        alias="path",
    )

    @property
    def base_uri(self) -> URI:
        """
        The current base URI, as on a plain `referencing.Resolver`.
        """
        return self._base_uri

    @property
    def path(self) -> tuple[exceptions.TrustBoundaryViolation.Hop, ...]:
        """
        The reference path followed to reach the current resource.
        """
        return self._path

    @property
    def layer(self) -> Registry[D]:
        """
        The isolated registry of external resources admitted so far.
        """
        return self._layer

    def _combined(self) -> Registry[D]:
        return self._boundary._trusted.registry.combine(  # type: ignore[reportPrivateUsage]
            self._layer,
        )

    def _violation(
        self,
        ref: URI,
        kind: str,
        claimed: URI,
        path: tuple[exceptions.TrustBoundaryViolation.Hop, ...],
    ) -> exceptions.TrustBoundaryViolation:
        return exceptions.TrustBoundaryViolation(
            ref=ref,
            kind=kind,
            claimed=claimed,
            path=path,
        )

    def _check_anchor(
        self,
        anchor: AnchorType[D],
        uri: URI,
        trusted: _TrustedSnapshot[D],
        layer: Registry[D],
        layer_dynamic_names: set[str],
        seen_anchor_keys: set[tuple[URI, str]],
        ref: URI,
        path: tuple[exceptions.TrustBoundaryViolation.Hop, ...],
    ) -> None:
        """
        Reject an anchor whose (resource, name) identity is already owned.

        Dynamic anchors are compared by name across the whole boundary so
        an external one can never shadow a trusted one; plain anchors are
        scoped to their containing resource URI. New anchors discovered
        during the current admission are tracked in ``seen_anchor_keys``.
        """
        key = (uri, anchor.name)
        if _is_dynamic_anchor(anchor):
            if (
                anchor.name in trusted.dynamic_anchor_names
                or anchor.name in layer_dynamic_names
            ):
                raise self._violation(
                    ref,
                    exceptions.TrustBoundaryViolation.DYNAMIC_ANCHOR,
                    f"{uri}#{anchor.name}",
                    path,
                )
            layer_dynamic_names.add(anchor.name)
            return
        if (
            key in trusted.anchors
            or key in _anchors_of(layer)
            or key in seen_anchor_keys
        ):
            raise self._violation(
                ref,
                exceptions.TrustBoundaryViolation.ANCHOR,
                f"{uri}#" + anchor.name,
                path,
            )

    def _admit(
        self,
        fetch_uri: URI,
        resource: Resource[D],
        ref: URI,
        path: tuple[exceptions.TrustBoundaryViolation.Hop, ...],
    ) -> tuple[Registry[D], Resource[D]]:
        """
        Admit a freshly retrieved external resource into the isolated layer.

        The resource is walked together with its subresources, mirroring
        `Registry.crawl` (relative ``$id`` resolution, fragment stripping),
        but every newly claimed URI, anchor and dynamic anchor name is
        checked against the trusted identities and the existing layer.

        The resource is indexed both under the URI it was fetched from and
        under its resolved internal identifier, matching the aliasing
        behavior of `Registry.get_or_retrieve`, so references spelled with
        either URI resolve. Returns the updated layer alongside the
        admitted root resource.
        """
        trusted = self._boundary._trusted  # type: ignore[reportPrivateUsage]
        layer = self._layer
        fetch_identity = _normalize(fetch_uri)

        resources = _resources_of(layer)
        anchors = _anchors_of(layer)
        layer_dynamic_names = {
            name
            for (_uri, name), anchor in anchors.items()
            if _is_dynamic_anchor(anchor)
        }

        # The root occupies both the URI it was fetched from and its
        # resolved internal identifier, so neither may be claimed by one of
        # its subresources. Reserve them before the walk.
        root_id = resource.id()
        if root_id is not None:
            root_uri = _normalize(urljoin(fetch_identity, root_id))
            if root_uri in trusted.uris or root_uri in _resources_of(layer):
                raise self._violation(
                    ref,
                    exceptions.TrustBoundaryViolation.RESOURCE,
                    root_uri,
                    path,
                )
        else:
            root_uri = fetch_identity
        seen_uris: set[URI] = {fetch_identity, root_uri}
        seen_anchor_keys: set[tuple[URI, str]] = set()

        resources = resources.insert(root_uri, resource)
        for anchor in resource.anchors():
            self._check_anchor(
                anchor=anchor,
                uri=root_uri,
                trusted=trusted,
                layer=layer,
                layer_dynamic_names=layer_dynamic_names,
                seen_anchor_keys=seen_anchor_keys,
                ref=ref,
                path=path,
            )
            seen_anchor_keys.add((root_uri, anchor.name))
            anchors = anchors.insert((root_uri, anchor.name), anchor)

        # Nodes carry the URI inherited from their parent; a node without
        # its own identifier does not claim a new identity.
        pending: list[tuple[URI, Resource[D]]] = [
            (root_uri, each) for each in resource.subresources()
        ]
        while pending:
            parent_uri, node = pending.pop()
            node_id = node.id()
            if node_id is not None:
                uri = _normalize(urljoin(parent_uri, node_id))
                if (
                    uri in trusted.uris
                    or uri in _resources_of(layer)
                    or uri in seen_uris
                ):
                    raise self._violation(
                        ref,
                        exceptions.TrustBoundaryViolation.RESOURCE,
                        uri,
                        path,
                    )
                seen_uris.add(uri)
            else:
                # A node without its own identifier inherits its parent's
                # identity, which has already been validated when the parent
                # was processed.
                uri = parent_uri

            if uri not in resources:
                resources = resources.insert(uri, node)

            for anchor in node.anchors():
                self._check_anchor(
                    anchor=anchor,
                    uri=uri,
                    trusted=trusted,
                    layer=layer,
                    layer_dynamic_names=layer_dynamic_names,
                    seen_anchor_keys=seen_anchor_keys,
                    ref=ref,
                    path=path,
                )
                seen_anchor_keys.add((uri, anchor.name))
                anchors = anchors.insert((uri, anchor.name), anchor)

            pending.extend((uri, each) for each in node.subresources())

        # Alias the fetch URI to the root resource when its internal
        # identifier claimed a different identity. The fetch URI was
        # reserved before the walk, so no subresource can have taken it.
        if fetch_identity != root_uri:
            resources = resources.insert(fetch_identity, resource)

        return (
            evolve(
                layer,
                resources=resources,
                anchors=anchors,
                uncrawled=EMPTY_UNCRAWLED,
            ),
            resource,
        )

    def _get_or_retrieve(
        self,
        target: URI,
        ref: URI,
        path: tuple[exceptions.TrustBoundaryViolation.Hop, ...],
    ) -> tuple[Registry[D], Resource[D]]:
        normalized = _normalize(target)

        external = _resources_of(self._layer).get(normalized)
        if external is not None:
            return self._layer, external

        trusted_registry = self._boundary._trusted.registry  # type: ignore[reportPrivateUsage]
        trusted = _resources_of(trusted_registry).get(normalized)
        if trusted is not None:
            return self._layer, trusted

        try:
            resource = self._boundary._retrieve(target)  # type: ignore[reportPrivateUsage]
        except (
            exceptions.CannotDetermineSpecification,
            exceptions.NoSuchResource,
        ):
            raise
        except Exception as error:
            raise exceptions.Unretrievable(ref=target) from error

        return self._admit(target, resource, ref=ref, path=path)

    def _push_path(
        self,
        via: str | None,
        ref: URI,
    ) -> tuple[exceptions.TrustBoundaryViolation.Hop, ...]:
        hop = exceptions.TrustBoundaryViolation.Hop(
            parent=self._base_uri or None,
            via=via,
            ref=urljoin(self._base_uri, ref),
        )
        return (*self._path, hop)

    def _evolve_previous(self, base_uri: URI) -> List[URI]:
        previous = self._previous
        if self._base_uri and (not previous or base_uri != self._base_uri):
            previous = previous.push_front(self._base_uri)
        return previous

    def lookup(self, ref: URI, *, via: str | None = None) -> Resolved[D]:
        """
        Resolve a reference, enforcing the trust boundary.

        ``via`` records the reference keyword followed (``"$ref"`` or
        ``"$dynamicRef"``). It defaults to ``"$ref"`` for non-fragment
        references and to ``None`` for entrypoint / fragment-only lookups.
        """
        if via is None:
            # The initial entrypoint lookup is not itself a reference
            # keyword; any hop taken once inside a document follows some
            # reference, which by default is recorded as a ``$ref``.
            via = REF if self._base_uri else None
        target, fragment = _resolve_ref(self._base_uri, ref)
        path = self._push_path(via, ref)

        try:
            layer, resource = self._get_or_retrieve(target, ref, path)
        except exceptions.NoSuchResource:
            raise exceptions.Unresolvable(ref=ref) from None
        except exceptions.Unretrievable as error:
            raise exceptions.Unresolvable(ref=ref) from error

        previous = self._evolve_previous(target)
        resolver = evolve(
            self,
            layer=layer,
            base_uri=target,
            previous=previous,
            path=path,
        )

        if fragment.startswith("/"):
            return resource.pointer(
                pointer=fragment,
                resolver=_as_plain(resolver),
            )
        if fragment:
            anchor = resolver._combined().anchor(target, fragment)
            return anchor.value.resolve(resolver=_as_plain(resolver))
        return Resolved(
            contents=resource.contents,
            resolver=_as_plain(resolver),
        )

    def lookup_dynamic(self, ref: URI) -> Resolved[D]:
        """
        Resolve a ``$dynamicRef``, enforcing the boundary.

        Identity admission (including the name-based dynamic-anchor
        protection) has already happened by the time the anchor is
        resolved, so an external dynamic anchor can never shadow a trusted
        one across the dynamic scope.
        """
        target, fragment = _resolve_ref(self._base_uri, ref)
        path = self._push_path(DYNAMIC_REF, ref)

        try:
            layer, resource = self._get_or_retrieve(target, ref, path)
        except exceptions.NoSuchResource:
            raise exceptions.Unresolvable(ref=ref) from None
        except exceptions.Unretrievable as error:
            raise exceptions.Unresolvable(ref=ref) from error

        previous = self._evolve_previous(target)
        resolver = evolve(
            self,
            layer=layer,
            base_uri=target,
            previous=previous,
            path=path,
        )

        if not fragment or fragment.startswith("/"):
            # Without a plain-name fragment a dynamic ref is an ordinary one.
            return self._plain_lookup(resolver, ref)

        from referencing.jsonschema import DynamicAnchor

        combined = resolver._combined()
        anchor = combined.anchor(target, fragment).value
        if not isinstance(anchor, DynamicAnchor):
            raise exceptions.NoSuchAnchor(
                ref=target,
                resource=resource,
                anchor=fragment,
            )
        # DynamicAnchor is JSON-Schema-specific and therefore typed over
        # Schema; within the generic boundary the same structural resolver
        # is used and the result is widened back to D.
        return cast(
            "Resolved[D]",
            anchor.resolve(resolver=cast("Resolver", _as_plain(resolver))),
        )

    def _plain_lookup(
        self,
        resolver: BoundResolver[D],
        ref: URI,
    ) -> Resolved[D]:
        # This is only reached for a dynamic ref without a plain-name
        # fragment: either an empty fragment (the whole resource) or a
        # JSON-pointer fragment.
        target, fragment = _resolve_ref(resolver._base_uri, ref)
        if fragment.startswith("/"):
            resource = resolver._combined()[target]
            return resource.pointer(
                pointer=fragment,
                resolver=_as_plain(resolver),
            )
        return Resolved(
            contents=resolver._combined()[target].contents,
            resolver=_as_plain(resolver),
        )

    def in_subresource(self, subresource: Resource[D]) -> BoundResolver[D]:
        """
        Enter a subresource, resolving its relative identifier.

        Nothing new is admitted here -- subresources are admitted when
        their containing external resource is crawled -- but the base URI
        moves exactly as on a plain `referencing.Resolver`.
        """
        id = subresource.id()
        if id is None:
            return self
        return evolve(self, base_uri=urljoin(self._base_uri, id))

    def dynamic_scope(self) -> Iterable[tuple[URI, Registry[D]]]:
        """
        Yield the URIs in the dynamic scope, innermost first.

        The registry paired with each URI contains the trusted resources
        plus every external resource admitted so far, so the JSON Schema
        `DynamicAnchor` machinery resolves against the same view the
        boundary itself enforces.
        """
        combined = self._combined()
        for uri in self._previous:
            yield uri, combined

    def as_plain_resolver(self) -> Resolver[D]:
        """
        Return an ordinary `referencing.Resolver` over the current view.

        The returned resolver shares the trusted registry and admitted
        layer but has no enforcement power; it is intended only for
        read-only inspection (e.g. tests and diagnostics).
        """
        return Resolver(
            base_uri=self._base_uri,
            registry=self._combined(),
            previous=self._previous,
        )
