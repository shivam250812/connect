"""The connector config language: models, validation and the forgiving intake for hand- or AI-written files."""

from connectforge.config.schema import (
                                        ENTITY_FIELDS,
                                        REQUIRED,
                                        TABLES,
                                        ConnectorSpec,
                                        FieldMap,
                                        SpecError,
                                        masked,
                                        parse_spec,
                                        parse_specs,
                                        parse_specs_with_fixes,
)

__all__ = ["ENTITY_FIELDS", "REQUIRED", "TABLES", "ConnectorSpec", "FieldMap", "SpecError", "masked", "parse_spec",
           "parse_specs", "parse_specs_with_fixes"]
