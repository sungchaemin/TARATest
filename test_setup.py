#!/usr/bin/env python3
"""
Test script to verify pipeline setup and basic functionality.
"""

import sys
from pathlib import Path


def test_imports():
    """Test that all pipeline modules can be imported."""
    print("Testing module imports...")

    try:
        import pipeline_types
        print("[OK] pipeline_types")
    except ImportError as e:
        print(f"[FAIL] pipeline_types: {e}")
        return False

    try:
        import step1_prepare_inputs
        print("[OK] step1_prepare_inputs")
    except ImportError as e:
        print(f"[FAIL] step1_prepare_inputs: {e}")
        return False

    try:
        import step2_decompose_attack
        print("[OK] step2_decompose_attack")
    except ImportError as e:
        print(f"[FAIL] step2_decompose_attack: {e}")
        return False

    try:
        import step3a_bind_controls
        print("[OK] step3a_bind_controls")
    except ImportError as e:
        print(f"[FAIL] step3a_bind_controls: {e}")
        return False

    try:
        import step3b_generate_scripts
        print("[OK] step3b_generate_scripts")
    except ImportError as e:
        print(f"[FAIL] step3b_generate_scripts: {e}")
        return False

    try:
        import step5_assemble_v3
        print("[OK] step5_assemble_v3")
    except ImportError as e:
        print(f"[FAIL] step5_assemble_v3: {e}")
        return False

    try:
        import pipeline_runner
        print("[OK] pipeline_runner")
    except ImportError as e:
        print(f"[FAIL] pipeline_runner: {e}")
        return False

    return True


def test_input_files():
    """Test that input files exist and are readable."""
    print("\nTesting input files...")

    current_dir = Path(__file__).parent
    inputs_dir = current_dir / "inputs"

    if not inputs_dir.exists():
        print(f"[FAIL] Inputs directory not found: {inputs_dir}")
        return False
    print(f"[OK] Inputs directory: {inputs_dir}")

    threats_path = inputs_dir / "threats.json"
    if not threats_path.exists():
        print(f"[FAIL] Threats file not found: {threats_path}")
        return False
    print(f"[OK] Threats file: {threats_path}")

    # Try to load the threats file
    try:
        from step1_prepare_inputs import load_json
        threats_data = load_json(threats_path)
        scenario_count = len(threats_data.get("scenarios", []))
        print(f"[OK] Threats file contains {scenario_count} scenarios")
    except Exception as e:
        print(f"[FAIL] Error loading threats file: {e}")
        return False

    # Check for system model (it might have different names)
    system_model_files = [
        "system_model.json",
        "jeep_whitepaper_function_level_all_implemented_fixed_v3_en.json"
    ]

    system_model_path = None
    for filename in system_model_files:
        test_path = inputs_dir / filename
        if test_path.exists():
            system_model_path = test_path
            break

    if system_model_path is None:
        print(f"[FAIL] No system model file found. Looked for: {system_model_files}")
        return False
    print(f"[OK] System model file: {system_model_path}")

    return True


def test_nist_optional():
    """Test that NIST SP 800-53 is properly optional."""
    print("\nTesting NIST SP 800-53 optional functionality...")

    try:
        from step3b_generate_scripts import _render_nist
        # This should work even without nist_catalog
        result = _render_nist(["AC-1", "AC-2"])
        # Avoid Unicode issues by just checking that it returns a string
        print(f"[OK] NIST renderer available: returned {type(result).__name__}")
        return True
    except Exception as e:
        print(f"[FAIL] NIST renderer failed: {e}")
        return False


def main():
    """Run all tests."""
    print("TARA Pipeline Setup Test")
    print("========================")

    tests = [
        ("Module Imports", test_imports),
        ("Input Files", test_input_files),
        ("NIST Optional", test_nist_optional),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            if test_func():
                passed += 1
                print(f"[OK] {test_name} PASSED")
            else:
                print(f"[FAIL] {test_name} FAILED")
        except Exception as e:
            print(f"[FAIL] {test_name} ERROR: {e}")

    print("\n" + "="*40)
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("[OK] All tests passed! Pipeline setup is ready.")
        print("\nNext steps:")
        print("1. Run: python example_run.py")
        print("2. Or: python pipeline_runner.py inputs/threats.json inputs/[system_model] output/")
        return 0
    else:
        print("[FAIL] Some tests failed. Check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())