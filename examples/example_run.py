#!/usr/bin/env python3
"""
Example usage of the TARA pipeline runner.

This demonstrates how to run the complete pipeline from attack tree inputs
to executable security test scripts.
"""

from pathlib import Path
from pipeline_runner import run_full_pipeline


def main():
    """Example pipeline execution."""

    # Input files (adjust paths as needed)
    current_dir = Path(__file__).parent
    threats_path = current_dir / "inputs" / "threats.json"
    system_model_path = current_dir / "inputs" / "system_model.json"
    output_dir = current_dir / "output"

    print("TARA Pipeline Example")
    print("====================")
    print(f"Threats file: {threats_path}")
    print(f"System model: {system_model_path}")
    print(f"Output directory: {output_dir}")
    print()

    # Check that input files exist
    if not threats_path.exists():
        print(f"Error: Threats file not found: {threats_path}")
        return 1

    if not system_model_path.exists():
        print(f"Error: System model file not found: {system_model_path}")
        return 1

    # Run the pipeline without LLM features (stub mode)
    # This will work without an API key
    print("Running pipeline in stub mode (no LLM features)...")
    print("Output will be saved in timestamped folder to preserve previous runs...")
    results = run_full_pipeline(
        threats_path=threats_path,
        system_model_path=system_model_path,
        output_base_dir=output_dir,
        scenario_ids=None,  # Process all scenarios
        api_key=None,  # No API key = stub mode
        enable_llm=False,  # Explicit disable
        use_timestamp=True,  # Create timestamped folder
        custom_run_name="example_run",  # Custom name for this example
    )

    print("\n" + "="*50)
    print("Pipeline Execution Complete!")
    print("="*50)
    print(f"Status: {results['status']}")
    print(f"Scenarios processed: {results['scenarios_processed']}")
    print(f"Attack paths generated: {results['paths_generated']}")
    print(f"Total scripts created: {len(results['scripts_created'])}")

    if results['scripts_created']:
        print("\nGenerated scripts:")
        for script_path in results['scripts_created']:
            print(f"  - {script_path}")

    if results['errors']:
        print("\nErrors encountered:")
        for error in results['errors']:
            print(f"  - {error}")
        return 1

    print(f"\nOutput files written to: {results['output_directory']}")
    print(f"Run completed at: {results['run_timestamp']}")
    print("\nTo run with LLM features:")
    print("1. Set ANTHROPIC_API_KEY environment variable")
    print("2. Call run_full_pipeline with enable_llm=True")
    print("\nEach run creates a separate timestamped folder to preserve previous results!")

    return 0


if __name__ == "__main__":
    exit(main())