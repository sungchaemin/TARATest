#!/usr/bin/env python3
"""
Pipeline Runner - orchestrates step-by-step execution with data flow
Implements the full TARA attack tree -> executable script pipeline
"""

import sys
from pathlib import Path
from typing import Any
from datetime import datetime

from pipeline_types import NormalizedScenario, ScenarioPlan
from step1_prepare_inputs import prepare_inputs
from step2_decompose_attack import decompose_scenarios, create_enricher
from step3a_bind_controls import bind_controls_for_scenario, create_llm_binder
from step3b_generate_scripts import generate_scripts_for_path, create_llm_generator
from step5_assemble_v3 import assemble_path


def run_full_pipeline(
    threats_path: Path | str,
    system_model_path: Path | str,
    output_base_dir: Path | str,
    scenario_ids: list[str] | None = None,
    api_key: str | None = None,
    enable_llm: bool = True,
    use_timestamp: bool = True,
    custom_run_name: str | None = None,
) -> dict[str, Any]:
    """
    Run the complete pipeline from TARA input files to executable scripts.

    Args:
        threats_path: Path to threats.json (TARA attack tree)
        system_model_path: Path to system_model.json (testbed config)
        output_base_dir: Base directory for outputs
        scenario_ids: Optional filter for specific scenarios
        api_key: Anthropic API key for LLM steps (if None, uses stubs)
        enable_llm: Whether to use LLM features (requires API key)
        use_timestamp: Create timestamped subfolder (default: True)
        custom_run_name: Custom name for run folder (overrides timestamp)

    Returns:
        Dictionary with pipeline results and metrics
    """
    # Create timestamped output directory to preserve previous runs
    if custom_run_name:
        run_folder = custom_run_name
    elif use_timestamp:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_folder = f"run_{timestamp}"
    else:
        run_folder = "latest"

    output_dir = Path(output_base_dir) / run_folder
    output_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "status": "running",
        "steps_completed": [],
        "scenarios_processed": 0,
        "paths_generated": 0,
        "scripts_created": [],
        "errors": [],
        "output_directory": str(output_dir),
        "run_timestamp": datetime.now().isoformat(),
    }

    try:
        # Step 1: Parse and normalize input files
        print("=== Step 1: Prepare Inputs ===")
        scenarios = prepare_inputs(
            threats_path=threats_path,
            system_model_path=system_model_path,
            scenario_ids=scenario_ids,
        )
        results["steps_completed"].append("step1_prepare_inputs")
        results["scenarios_processed"] = len(scenarios)
        print(f"Step 1 complete: {len(scenarios)} scenarios prepared")

        # Step 2: Decompose attack trees into plans
        print("=== Step 2: Decompose Attack ===")
        enricher = None
        if enable_llm and api_key:
            enricher = create_enricher(api_key=api_key)

        scenario_plans = decompose_scenarios(scenarios, enricher=enricher)
        results["steps_completed"].append("step2_decompose_attack")

        # Create lookup for step plans by scenario and path
        step_plans_by_scenario = {}
        for scenario, plan in zip(scenarios, scenario_plans):
            if hasattr(plan, 'path_plans'):
                # New schema with per-path plans
                step_plans_by_scenario[scenario.scenario_id] = {
                    pp.path_id: pp.steps for pp in plan.path_plans
                }
            else:
                # Legacy single plan
                step_plans_by_scenario[scenario.scenario_id] = {
                    "default": plan.steps if hasattr(plan, 'steps') else []
                }

        print(f"Step 2 complete: {len(scenario_plans)} scenario plans created")

        # Process each scenario through the remaining steps
        for scenario_idx, scenario in enumerate(scenarios):
            scenario_plan = scenario_plans[scenario_idx]

            print(f"=== Processing scenario: {scenario.scenario_id} ===")

            # Step 3A: Bind controls to steps
            print("=== Step 3A: Bind Controls ===")
            binder = None
            if enable_llm and api_key:
                binder = create_llm_binder(api_key=api_key)

            # Get step plans for this scenario
            plan_by_path = step_plans_by_scenario.get(scenario.scenario_id, {})

            path_bindings = bind_controls_for_scenario(
                scenario=scenario,
                binder=binder,
                plan_by_path=plan_by_path,
            )

            print(f"Step 3A complete: {len(path_bindings)} path bindings created")

            # Process each path in the scenario
            for path_idx, path in enumerate(scenario.attack_paths):
                path_binding = path_bindings[path_idx]

                print(f"=== Processing path: {path.path_id} ===")

                # Step 3B: Generate scripts for each step
                print("=== Step 3B: Generate Scripts ===")
                generator = None
                if enable_llm and api_key:
                    generator = create_llm_generator(api_key=api_key)

                # Get step plans for this specific path
                path_plan_steps = plan_by_path.get(path.path_id, [])

                step_scripts = generate_scripts_for_path(
                    scenario=scenario,
                    path=path,
                    bindings=path_binding.bindings,
                    generator=generator,
                    path_plan_steps=path_plan_steps,
                    cache_dir=output_dir / "cache",
                )

                print(f"Step 3B complete: {len(step_scripts)} scripts generated")

                # Write individual step scripts to disk
                steps_dir = output_dir / "steps" / scenario.scenario_id / path.path_id
                steps_dir.mkdir(parents=True, exist_ok=True)

                for script in step_scripts:
                    script_path = steps_dir / f"{script.step_id}.py"
                    script_path.write_text(script.code, encoding="utf-8")
                    results["scripts_created"].append(str(script_path))

                # Step 5: Assemble final executable script
                print("=== Step 5: Assemble Script ===")
                assembled_script_path = assemble_path(
                    scenario=scenario,
                    path=path,
                    steps_dir=steps_dir,
                    out_dir=output_dir / "assembled",
                )

                results["scripts_created"].append(str(assembled_script_path))
                results["paths_generated"] += 1

                print(f"Step 5 complete: {assembled_script_path}")

        results["steps_completed"].extend([
            "step3a_bind_controls",
            "step3b_generate_scripts",
            "step5_assemble"
        ])
        results["status"] = "completed"

    except Exception as e:
        results["status"] = "failed"
        results["errors"].append(str(e))
        print(f"Pipeline failed: {e}", file=sys.stderr)
        raise

    return results


def main():
    """CLI entry point for the pipeline runner."""
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Run the complete TARA pipeline")
    parser.add_argument("threats", help="Path to threats.json")
    parser.add_argument("system_model", help="Path to system_model.json")
    parser.add_argument("output_dir", help="Output directory for generated scripts")
    parser.add_argument(
        "--scenarios",
        nargs="*",
        help="Optional: specific scenario IDs to process"
    )
    parser.add_argument(
        "--api-key",
        help="Anthropic API key (or set ANTHROPIC_API_KEY env var)"
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM features (use stubs only)"
    )
    parser.add_argument(
        "--no-timestamp",
        action="store_true",
        help="Don't create timestamped subfolder (overwrites previous runs)"
    )
    parser.add_argument(
        "--run-name",
        help="Custom name for run folder (e.g., 'test_run_v1')"
    )

    args = parser.parse_args()

    # Get API key from args or environment
    api_key = args.api_key or os.getenv("ANTHROPIC_API_KEY")
    enable_llm = not args.no_llm

    if enable_llm and not api_key:
        print("Warning: No API key provided. LLM features disabled.", file=sys.stderr)
        enable_llm = False

    # Run the pipeline
    results = run_full_pipeline(
        threats_path=args.threats,
        system_model_path=args.system_model,
        output_base_dir=args.output_dir,
        scenario_ids=args.scenarios,
        api_key=api_key,
        enable_llm=enable_llm,
        use_timestamp=not args.no_timestamp,
        custom_run_name=args.run_name,
    )

    # Print results summary
    print("\n=== Pipeline Results ===")
    print(f"Status: {results['status']}")
    print(f"Output directory: {results['output_directory']}")
    print(f"Run timestamp: {results['run_timestamp']}")
    print(f"Scenarios processed: {results['scenarios_processed']}")
    print(f"Paths generated: {results['paths_generated']}")
    print(f"Scripts created: {len(results['scripts_created'])}")

    if results["errors"]:
        print("Errors:")
        for error in results["errors"]:
            print(f"  - {error}")

    return 0 if results["status"] == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())