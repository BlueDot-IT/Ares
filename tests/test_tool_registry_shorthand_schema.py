from ares.tools.registry import ToolRegistry


def test_registry_promotes_json_schema_shorthand_to_function_parameters() -> None:
    registry = ToolRegistry()
    registry.register(
        name="required_input",
        toolset="unit",
        risk="passive",
        schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
        handler=lambda args, **_: args,
        description="Require a target.",
    )

    definition = registry.get_tool_definitions()[0]["function"]

    assert definition["name"] == "required_input"
    assert definition["description"] == "Require a target."
    assert definition["parameters"]["properties"] == {
        "target": {"type": "string"}
    }
    assert definition["parameters"]["required"] == ["target"]
