import logging
import re
from functools import wraps

from flask import Response, request, url_for

import features
from app import app, model_cache, pullmetrics, storage
from auth.registry_jwt_auth import process_registry_jwt_auth
from data.database import db_disallow_replica_use
from data.model import (
    ImmutableTagException,
    ManifestDoesNotExist,
    QuotaExceededException,
    RepositoryDoesNotExist,
    TagDoesNotExist,
    namespacequota,
)
from data.model.oci import tag as oci_tag
from data.model.oci.manifest import CreateManifestException
from data.model.oci.tag import RetargetTagException
from data.registry_model import registry_model
from digest import digest_tools
from endpoints.api import (
    log_unauthorized_delete,
    log_unauthorized_pull,
    log_unauthorized_push,
)
from endpoints.decorators import (
    anon_protect,
    check_pushes_disabled,
    check_readonly,
    disallow_for_account_recovery_mode,
    inject_registry_model,
    parse_repository_name,
)
from endpoints.metrics import image_pulls, image_pushes
from endpoints.v2 import require_repo_read, require_repo_write, v2_bp
from endpoints.v2.errors import (
    InvalidRequest,
    ManifestInvalid,
    ManifestUnknown,
    NameInvalid,
    NameUnknown,
    QuotaExceeded,
    TagExpired,
    TagImmutable,
)
from image.docker.schema1 import (
    DOCKER_SCHEMA1_CONTENT_TYPES,
    DOCKER_SCHEMA1_MANIFEST_CONTENT_TYPE,
    DockerSchema1Manifest,
)
from image.docker.schema2 import DOCKER_SCHEMA2_CONTENT_TYPES
from image.oci import OCI_CONTENT_TYPES
from image.shared import ManifestException
from image.shared.schemas import parse_manifest_from_bytes
from notifications import spawn_notification
from util.audit import track_and_log
from util.bytes import Bytes
from util.names import VALID_TAG_PATTERN
from util.registry.replication import queue_replication_batch

logger = logging.getLogger(__name__)

BASE_MANIFEST_ROUTE = '/<repopath:repository>/manifests/<regex("{0}"):manifest_ref>'
MANIFEST_DIGEST_ROUTE = BASE_MANIFEST_ROUTE.format(digest_tools.DIGEST_PATTERN)
MANIFEST_TAGNAME_ROUTE = BASE_MANIFEST_ROUTE.format(VALID_TAG_PATTERN)


@v2_bp.route(MANIFEST_TAGNAME_ROUTE, methods=["GET"])
@disallow_for_account_recovery_mode
@parse_repository_name()
@process_registry_jwt_auth(scopes=["pull"])
@log_unauthorized_pull
@require_repo_read(allow_for_superuser=True, allow_for_global_readonly_superuser=True)
@anon_protect
@inject_registry_model()
def fetch_manifest_by_tagname(namespace_name, repo_name, manifest_ref, registry_model):
    try:
        repository_ref = registry_model.lookup_repository(
            namespace_name,
            repo_name,
            raise_on_error=True,
            manifest_ref=manifest_ref,
            model_cache=model_cache,
        )
    except RepositoryDoesNotExist as e:
        image_pulls.labels("v2", "tag", 404).inc()
        raise NameUnknown("repository not found")

    try:
        tag = registry_model.get_repo_tag(repository_ref, manifest_ref, raise_on_error=True)
    except TagDoesNotExist as e:
        if registry_model.has_expired_tag(repository_ref, manifest_ref):
            logger.debug(
                "Found expired tag %s for repository %s/%s", manifest_ref, namespace_name, repo_name
            )
            msg = (
                "Tag %s was deleted or has expired. To pull, revive via time machine" % manifest_ref
            )
            image_pulls.labels("v2", "tag", 404).inc()
            raise TagExpired(msg)

        image_pulls.labels("v2", "tag", 404).inc()
        raise ManifestUnknown(str(e))

    manifest = registry_model.get_manifest_for_tag(tag)
    if manifest is None:
        # Something went wrong.
        image_pulls.labels("v2", "tag", 400).inc()
        raise ManifestInvalid()

    try:
        manifest_bytes, manifest_digest, manifest_media_type = _rewrite_schema_if_necessary(
            namespace_name, repo_name, manifest_ref, manifest, registry_model
        )
    except (ManifestException, ManifestDoesNotExist) as e:
        image_pulls.labels("v2", "tag", 404).inc()
        raise ManifestUnknown(str(e))

    if manifest_bytes is None:
        image_pulls.labels("v2", "tag", 404).inc()
        raise ManifestUnknown()

    track_and_log(
        "pull_repo",
        repository_ref,
        analytics_name="pull_repo_100x",
        analytics_sample=0.01,
        tag=manifest_ref,
        mediaType=manifest_media_type,
    )
    image_pulls.labels("v2", "tag", 200).inc()

    # Track pull metrics if feature is enabled
    if features.IMAGE_PULL_STATS:
        try:
            if pullmetrics:
                metrics = pullmetrics.get_event()
                metrics.track_tag_pull(repository_ref, manifest_ref, manifest_digest)
        except Exception as e:
            logger.warning(
                "Could not track tag pull metrics: %s. " "Pull statistics may not be recorded.",
                str(e),
            )

    return Response(
        manifest_bytes.as_unicode(),
        status=200,
        headers={
            "Content-Type": manifest_media_type,
            "Docker-Content-Digest": manifest_digest,
        },
    )


@v2_bp.route(MANIFEST_DIGEST_ROUTE, methods=["GET"])
@disallow_for_account_recovery_mode
@parse_repository_name()
@process_registry_jwt_auth(scopes=["pull"])
@log_unauthorized_pull
@require_repo_read(allow_for_superuser=True, allow_for_global_readonly_superuser=True)
@anon_protect
@inject_registry_model()
def fetch_manifest_by_digest(namespace_name, repo_name, manifest_ref, registry_model):
    try:
        repository_ref = registry_model.lookup_repository(
            namespace_name,
            repo_name,
            raise_on_error=True,
            manifest_ref=manifest_ref,
            model_cache=model_cache,
        )
    except RepositoryDoesNotExist as e:
        image_pulls.labels("v2", "manifest", 404).inc()
        raise NameUnknown("repository not found")

    try:
        manifest = registry_model.lookup_cached_manifest_by_digest(
            model_cache,
            repository_ref,
            manifest_ref,
            raise_on_error=True,
            allow_hidden=True,
        )
    except ManifestDoesNotExist as e:
        image_pulls.labels("v2", "manifest", 404).inc()
        raise ManifestUnknown(str(e))

    track_and_log(
        "pull_repo", repository_ref, manifest_digest=manifest_ref, mediaType=manifest.media_type
    )
    image_pulls.labels("v2", "manifest", 200).inc()

    # Track pull metrics if feature is enabled
    if features.IMAGE_PULL_STATS:
        try:
            if pullmetrics:
                metrics = pullmetrics.get_event()
                metrics.track_manifest_pull(repository_ref, manifest_ref)
        except Exception as e:
            logger.warning(
                "Could not track manifest pull metrics: %s. "
                "Pull statistics may not be recorded.",
                str(e),
            )

    return Response(
        manifest.internal_manifest_bytes.as_unicode(),
        status=200,
        headers={
            "Content-Type": manifest.media_type,
            "Docker-Content-Digest": manifest.digest,
        },
    )


def _rewrite_schema_if_necessary(
    namespace_name, repo_name, tag_name, manifest, registry_model=registry_model
):
    # As per the Docker protocol, if the manifest is not schema version 1 and the manifest's
    # media type is not in the Accept header, we return a schema 1 version of the manifest for
    # the amd64+linux platform, if any, or None if none.
    # See: https://docs.docker.com/registry/spec/manifest-v2-2
    mimetypes = [mimetype for mimetype, _ in request.accept_mimetypes]
    if manifest.media_type in mimetypes:
        return manifest.internal_manifest_bytes, manifest.digest, manifest.media_type

    # Short-circuit check: If the mimetypes is empty or just `application/json`, verify we have
    # a schema 1 manifest and return it.
    if not mimetypes or mimetypes == ["application/json"]:
        if manifest.media_type in DOCKER_SCHEMA1_CONTENT_TYPES:
            return manifest.internal_manifest_bytes, manifest.digest, manifest.media_type

    logger.debug(
        "Manifest `%s` not compatible against %s; checking for conversion",
        manifest.digest,
        request.accept_mimetypes,
    )
    converted = registry_model.convert_manifest(
        manifest, namespace_name, repo_name, tag_name, mimetypes, storage
    )
    if converted is not None:
        return converted.bytes, converted.digest, converted.media_type

    # For back-compat, we always default to schema 1 if the manifest could not be converted.
    schema1 = registry_model.get_schema1_parsed_manifest(
        manifest, namespace_name, repo_name, tag_name, storage, raise_on_error=True
    )
    return schema1.bytes, schema1.digest, schema1.media_type


def _reject_manifest2_schema2(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        namespace_name = kwargs["namespace_name"]
        if (
            request.content_type
            and request.content_type != "application/json"
            and request.content_type
            not in DOCKER_SCHEMA1_CONTENT_TYPES | DOCKER_SCHEMA2_CONTENT_TYPES | OCI_CONTENT_TYPES
        ):
            raise ManifestInvalid(
                detail={"message": "manifest schema version not supported"}, http_status_code=415
            )

        if namespace_name not in app.config.get("V22_NAMESPACE_BLACKLIST", []):
            if request.content_type in OCI_CONTENT_TYPES:
                if (
                    namespace_name not in app.config.get("OCI_NAMESPACE_WHITELIST", [])
                    and not features.GENERAL_OCI_SUPPORT
                ):
                    raise ManifestInvalid(
                        detail={"message": "manifest schema version not supported"},
                        http_status_code=415,
                    )

            return func(*args, **kwargs)

        if (
            _doesnt_accept_schema_v1()
            or request.content_type in DOCKER_SCHEMA2_CONTENT_TYPES | OCI_CONTENT_TYPES
        ):
            raise ManifestInvalid(
                detail={"message": "manifest schema version not supported"}, http_status_code=415
            )
        return func(*args, **kwargs)

    return wrapped


def _doesnt_accept_schema_v1():
    # If the client doesn't specify anything, still give them Schema v1.
    return (
        len(request.accept_mimetypes) != 0
        and DOCKER_SCHEMA1_MANIFEST_CONTENT_TYPE not in request.accept_mimetypes
    )


@v2_bp.route(MANIFEST_TAGNAME_ROUTE, methods=["PUT"])
@disallow_for_account_recovery_mode
@parse_repository_name()
@_reject_manifest2_schema2
@process_registry_jwt_auth(scopes=["pull", "push"])
@log_unauthorized_push
@require_repo_write(allow_for_superuser=True, disallow_for_restricted_users=True)
@anon_protect
@check_readonly
@check_pushes_disabled
def write_manifest_by_tagname(namespace_name, repo_name, manifest_ref):
    parsed = _parse_manifest(request.content_type, request.data)

    return _write_manifest_and_log(namespace_name, repo_name, manifest_ref, parsed)


def _enqueue_blobs_for_replication(manifest, storage, namespace_name):
    blobs = registry_model.get_manifest_local_blobs(manifest, storage)
    if blobs is None:
        logger.error("Could not lookup blobs for manifest `%s`", manifest.digest)
    else:
        with queue_replication_batch(namespace_name) as queue_storage_replication:
            for blob_digest in blobs:
                queue_storage_replication(blob_digest)


@v2_bp.route(MANIFEST_DIGEST_ROUTE, methods=["PUT"])
@disallow_for_account_recovery_mode
@parse_repository_name()
@_reject_manifest2_schema2
@process_registry_jwt_auth(scopes=["pull", "push"])
@log_unauthorized_push
@require_repo_write(allow_for_superuser=True, disallow_for_restricted_users=True)
@anon_protect
@check_readonly
@check_pushes_disabled
def write_manifest_by_digest(namespace_name, repo_name, manifest_ref):
    parsed = _parse_manifest(request.content_type, request.data)

    # Determine if this is a non-SHA-256 digest push
    parsed_ref = digest_tools.Digest.parse_digest(manifest_ref)
    is_alias_digest = parsed_ref.hash_alg != "sha256"

    if is_alias_digest:
        # Require FEATURE_MULTI_ALGORITHM_SUPPORT for non-SHA-256 digests
        if not app.config.get("FEATURE_MULTI_ALGORITHM_SUPPORT", False):
            image_pushes.labels("v2", 400, "").inc()
            raise ManifestInvalid(detail={"message": "non-SHA-256 digest not supported"})

        # Validate algorithm is allowed
        # TODO: Move _validate_digest_algorithm to digest/digest_tools.py in a follow-up
        from endpoints.v2.blob import _validate_digest_algorithm

        _validate_digest_algorithm(manifest_ref)

        # Reject non-SHA-256 for Schema v1 manifests (out of scope per spec)
        if parsed.schema_version != 2:
            image_pushes.labels("v2", 400, "").inc()
            raise ManifestInvalid(
                detail={"message": "non-SHA-256 digest not supported for Schema v1 manifests"}
            )

        # Compute the requested algorithm's hash of the manifest body
        computed = digest_tools.compute_digest(parsed_ref.hash_alg, request.data)
        if computed != manifest_ref:
            image_pushes.labels("v2", 400, "").inc()
            raise ManifestInvalid(detail={"message": "digest mismatch"})
    else:
        # SHA-256: use existing comparison
        if parsed.digest != manifest_ref:
            image_pushes.labels("v2", 400, "").inc()
            raise ManifestInvalid(detail={"message": "manifest digest mismatch"})

    # Handle tag query parameters (OCI end-7b)
    tag_names = request.args.getlist("tag")
    # Deduplicate while preserving order
    seen = set()
    unique_tags = []
    for t in tag_names:
        if t not in seen:
            seen.add(t)
            unique_tags.append(t)
    tag_names = unique_tags

    # Enforce tag limit
    max_tags = app.config.get("MULTI_ALGO_MAX_TAGS_PER_REQUEST", 100)
    if len(tag_names) > max_tags:
        raise InvalidRequest(message=f"Too many tags: {len(tag_names)} exceeds limit of {max_tags}")

    # Validate tag names
    for t in tag_names:
        if not re.fullmatch(VALID_TAG_PATTERN, t):
            raise InvalidRequest(message=f"Invalid tag name: {t}")

    # Schema v1 handling: if no alias digest and no tag params, fall through to
    # existing tag-based write using the embedded tag name
    if parsed.schema_version != 2 and not tag_names and not is_alias_digest:
        return _write_manifest_and_log(namespace_name, repo_name, parsed.tag, parsed)

    with db_disallow_replica_use():
        repository_ref = registry_model.lookup_repository(
            namespace_name, repo_name, model_cache=model_cache
        )
        if repository_ref is None:
            image_pushes.labels("v2", 404, "").inc()
            raise NameUnknown("repository not found")

        manifest = None
        tag = None
        created_tags = []

        if tag_names:
            # Use create_manifest_and_retarget_tag for the FIRST tag
            # (handles manifest creation + quota verification)
            first_tag = tag_names[0]
            try:
                manifest, tag = registry_model.create_manifest_and_retarget_tag(
                    repository_ref,
                    parsed,
                    first_tag,
                    storage,
                    raise_on_error=True,
                    verify_quota=app.config.get("FEATURE_QUOTA_MANAGEMENT", False)
                    and app.config.get("FEATURE_VERIFY_QUOTA", True),
                )
            except CreateManifestException as cme:
                raise ManifestInvalid(detail={"message": str(cme)})
            except RetargetTagException as rte:
                raise ManifestInvalid(detail={"message": str(rte)})
            except ImmutableTagException:
                # First tag is immutable -- still create manifest with temp tag
                logger.warning("Skipping immutable tag %s during end-7b push", first_tag)
                # Fall back to temp tag for manifest creation
                expiration_sec = app.config["PUSH_TEMP_TAG_EXPIRATION_SEC"]
                manifest = registry_model.create_manifest_with_temp_tag(
                    repository_ref,
                    parsed,
                    expiration_sec,
                    storage,
                )
                if manifest is None:
                    image_pushes.labels("v2", 400, "").inc()
                    raise ManifestInvalid()
            except QuotaExceededException:
                raise QuotaExceeded()

            if manifest is None:
                image_pushes.labels("v2", 400, "").inc()
                raise ManifestInvalid()

            # If first tag succeeded, record it
            if tag is not None:
                created_tags.append(first_tag)

            # Use oci.tag.retarget_tag() directly for subsequent tags
            for tag_name in tag_names[1:]:
                try:
                    result_tag = oci_tag.retarget_tag(
                        tag_name,
                        manifest._db_id,
                        raise_on_error=True,
                    )
                    if result_tag is not None:
                        created_tags.append(tag_name)
                except ImmutableTagException:
                    logger.warning("Skipping immutable tag %s during end-7b push", tag_name)
                    continue
                except RetargetTagException:
                    logger.warning(
                        "Failed to create tag %s during end-7b push",
                        tag_name,
                        exc_info=True,
                    )
                    continue
        else:
            # No tags: create manifest with temp tag (existing behavior)
            expiration_sec = app.config["PUSH_TEMP_TAG_EXPIRATION_SEC"]
            manifest = registry_model.create_manifest_with_temp_tag(
                repository_ref,
                parsed,
                expiration_sec,
                storage,
            )
            if manifest is None:
                image_pushes.labels("v2", 400, "").inc()
                raise ManifestInvalid()

        # Create DigestAlias for non-SHA-256 digest
        if is_alias_digest:
            _create_manifest_digest_alias(manifest_ref, manifest, repository_ref)

        image_pushes.labels("v2", 201, manifest.media_type).inc()

        # Queue blobs for replication
        if features.STORAGE_REPLICATION:
            _enqueue_blobs_for_replication(manifest, storage, namespace_name)

        # Audit logging and notifications for created tags
        for tag_name in created_tags:
            track_and_log(
                "push_repo",
                repository_ref,
                tag=tag_name,
                mediaType=manifest.media_type,
            )
        if created_tags:
            spawn_notification(
                repository_ref,
                "repo_push",
                {"updated_tags": created_tags},
            )

        # Build response headers
        headers = {
            "Docker-Content-Digest": manifest.digest,
            "Location": url_for(
                "v2.fetch_manifest_by_digest",
                repository="%s/%s" % (namespace_name, repo_name),
                manifest_ref=manifest.digest,
            ),
        }

        # Add OCI-Tag header for successfully created tags
        if created_tags:
            headers["OCI-Tag"] = ", ".join(created_tags)

        return Response("OK", status=201, headers=headers)


def _create_manifest_digest_alias(alias_digest, manifest, repository_ref):
    """
    Creates a DigestAlias for a manifest pushed by non-SHA-256 digest.
    Sets manifest_id FK for unambiguous manifest alias lookup.
    Links image_storage to one of the manifest's ManifestBlob storage rows
    (to satisfy the NOT NULL FK constraint).
    """
    from data.database import Manifest as ManifestTable
    from data.database import ManifestBlob as ManifestBlobTable
    from data.model.blob import DigestAliasCollisionError, create_digest_alias

    # Find a ManifestBlob for this manifest in this repository
    try:
        manifest_blob = (
            ManifestBlobTable.select()
            .where(
                ManifestBlobTable.manifest == manifest._db_id,
                ManifestBlobTable.repository == repository_ref._db_id,
            )
            .get()
        )
        image_storage = manifest_blob.blob

        # Get the manifest DB row for the FK
        manifest_row = ManifestTable.get(ManifestTable.id == manifest._db_id)

        try:
            create_digest_alias(
                alias_digest,
                image_storage,
                manifest=manifest_row,
            )
        except DigestAliasCollisionError:
            logger.warning(
                "DigestAlias collision for manifest alias %s, ignoring",
                alias_digest,
            )
    except ManifestBlobTable.DoesNotExist:
        logger.warning(
            "No ManifestBlob found for manifest %s, cannot create DigestAlias",
            manifest.digest,
        )


def _parse_manifest(content_type, request_data):
    content_type = content_type or DOCKER_SCHEMA1_MANIFEST_CONTENT_TYPE
    if content_type == "application/json":
        # For back-compat.
        content_type = DOCKER_SCHEMA1_MANIFEST_CONTENT_TYPE

    try:
        return parse_manifest_from_bytes(
            Bytes.for_string_or_unicode(request_data),
            content_type,
        )
    except ManifestException as me:
        logger.exception("failed to parse manifest when writing by tagname")
        raise ManifestInvalid(detail={"message": "failed to parse manifest: %s" % me})


@v2_bp.route(MANIFEST_DIGEST_ROUTE, methods=["DELETE"])
@disallow_for_account_recovery_mode
@parse_repository_name()
@process_registry_jwt_auth(scopes=["pull", "push"])
@log_unauthorized_delete
@require_repo_write(allow_for_superuser=True, disallow_for_restricted_users=True)
@anon_protect
@check_readonly
@check_pushes_disabled
def delete_manifest_by_digest(namespace_name, repo_name, manifest_ref):
    """
    Delete the manifest specified by the digest.

    Note: there is no equivalent method for deleting by tag name because it is
    forbidden by the spec.
    """
    with db_disallow_replica_use():
        repository_ref = registry_model.lookup_repository(
            namespace_name, repo_name, model_cache=model_cache
        )
        if repository_ref is None:
            raise NameUnknown("repository not found")

        manifest = registry_model.lookup_manifest_by_digest(repository_ref, manifest_ref)
        if manifest is None:
            raise ManifestUnknown()

        try:
            tags = registry_model.delete_tags_for_manifest(model_cache, manifest)
        except ImmutableTagException as ite:
            raise TagImmutable(detail={"message": f"tag '{ite.tag_name}' is immutable"}) from ite
        if not tags:
            raise ManifestUnknown()

        for tag in tags:
            track_and_log("delete_tag", repository_ref, tag=tag.name, digest=manifest_ref)

        return Response(status=202)


@v2_bp.route(MANIFEST_TAGNAME_ROUTE, methods=["DELETE"])
@disallow_for_account_recovery_mode
@parse_repository_name()
@process_registry_jwt_auth(scopes=["pull", "push"])
@log_unauthorized_delete
@require_repo_write(allow_for_superuser=True, disallow_for_restricted_users=True)
@anon_protect
@check_readonly
@check_pushes_disabled
def delete_manifest_by_tag(namespace_name, repo_name, manifest_ref):
    """
    Deletes the manifest specified by the tag.
    """
    with db_disallow_replica_use():
        repository_ref = registry_model.lookup_repository(
            namespace_name, repo_name, model_cache=model_cache
        )
        if repository_ref is None:
            raise NameUnknown("repository not found")

        tag = registry_model.get_repo_tag(repository_ref, manifest_ref)
        if tag is None:
            raise ManifestUnknown()

        try:
            deleted_tag = registry_model.delete_tag(model_cache, repository_ref, manifest_ref)
        except ImmutableTagException as ite:
            raise TagImmutable(detail={"message": f"tag '{ite.tag_name}' is immutable"}) from ite

        if not deleted_tag:
            raise ManifestUnknown()

        track_and_log("delete_tag", repository_ref, tag=deleted_tag.name, digest=manifest_ref)
        return Response(status=202)


def _write_manifest_and_log(namespace_name, repo_name, tag_name, manifest_impl):
    _validate_schema1_manifest(namespace_name, repo_name, manifest_impl)
    with db_disallow_replica_use():
        repository_ref, manifest, tag = _write_manifest(
            namespace_name, repo_name, tag_name, manifest_impl
        )

        # Queue all blob manifests for replication
        if features.STORAGE_REPLICATION:
            _enqueue_blobs_for_replication(manifest, storage, namespace_name)

        track_and_log("push_repo", repository_ref, tag=tag_name, mediaType=manifest.media_type)
        spawn_notification(repository_ref, "repo_push", {"updated_tags": [tag_name]})
        image_pushes.labels("v2", 201, manifest.media_type).inc()

        return Response(
            "OK",
            status=201,
            headers={
                "Docker-Content-Digest": manifest.digest,
                "Location": url_for(
                    "v2.fetch_manifest_by_digest",
                    repository="%s/%s" % (namespace_name, repo_name),
                    manifest_ref=manifest.digest,
                ),
            },
        )


def _write_manifest(
    namespace_name, repo_name, tag_name, manifest_impl, registry_model=registry_model
):
    # Ensure that the repository exists.
    repository_ref = registry_model.lookup_repository(
        namespace_name, repo_name, model_cache=model_cache
    )
    if repository_ref is None:
        raise NameUnknown("repository not found")

    # Create the manifest(s) and retarget the tag to point to it.
    try:
        manifest, tag = registry_model.create_manifest_and_retarget_tag(
            repository_ref,
            manifest_impl,
            tag_name,
            storage,
            raise_on_error=True,
            verify_quota=app.config.get("FEATURE_QUOTA_MANAGEMENT", False)
            and app.config.get("FEATURE_VERIFY_QUOTA", True),
        )
    except CreateManifestException as cme:
        raise ManifestInvalid(detail={"message": str(cme)})
    except RetargetTagException as rte:
        raise ManifestInvalid(detail={"message": str(rte)})
    except ImmutableTagException as ite:
        raise TagImmutable(detail={"message": f"tag '{ite.tag_name}' is immutable"}) from ite
    except QuotaExceededException as qee:
        raise QuotaExceeded()

    if manifest is None:
        raise ManifestInvalid()

    return repository_ref, manifest, tag


def _validate_schema1_manifest(namespace: str, repo: str, manifest: DockerSchema1Manifest):
    # NOTE: These extra checks are needed for schema version 1 because the manifests
    # contain the repo namespace, name and tag name.
    if manifest.schema_version != 1:
        return

    if (
        manifest.namespace == ""
        and features.LIBRARY_SUPPORT
        and namespace == app.config["LIBRARY_NAMESPACE"]
    ):
        pass
    elif manifest.namespace != namespace:
        raise NameInvalid(
            message="namespace name does not match manifest",
            detail={
                "message": "namespace name `%s` does not match `%s` in manifest"
                % (namespace, manifest.namespace),
            },
        )

    if manifest.repo_name != repo:
        raise NameInvalid(
            message="repository name does not match manifest",
            detail={
                "message": "repository name `%s` does not match `%s` in manifest"
                % (repo, manifest.repo_name),
            },
        )

    try:
        if not manifest.layers:
            raise ManifestInvalid(detail={"message": "manifest does not reference any layers"})
    except ManifestException as me:
        raise ManifestInvalid(detail={"message": str(me)})
