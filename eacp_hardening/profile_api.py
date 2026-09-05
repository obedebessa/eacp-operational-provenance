"""Use the same Profile 1.3 bytes in a checkout and an installed wheel."""
try:
    from eacp_profile.eacp_profile import ProfileError, validate_collection, resolve_record_links
except ModuleNotFoundError as exc:
    if exc.name not in {'eacp_profile', 'eacp_profile.eacp_profile'}:
        raise
    from spec.tools.eacp_profile import ProfileError, validate_collection, resolve_record_links

__all__ = ['ProfileError', 'validate_collection', 'resolve_record_links']
