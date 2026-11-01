"""Mapping engine (FR-5): source records -> the common schema, written by hand or learned automatically."""

from connectforge.mapping.inference import (
           SYNONYMS,
           find_next,
           find_records,
           infer_mapping,
           mapping_yaml,
)
from connectforge.mapping.mapper import map_field, map_record, preview
from connectforge.mapping.paths import (
           MappingError,
           get_path,
           parse_cef,
           parse_datetime,
           set_path,
           xml_to_dict,
)

__all__ = ["SYNONYMS", "MappingError", "find_next", "find_records", "get_path", "infer_mapping", "map_field", "map_record",
           "mapping_yaml", "parse_cef", "parse_datetime", "preview", "set_path", "xml_to_dict"]
